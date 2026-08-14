package leak

// Reproducer for the pod_state stale-FD "blackhole" bug.
//
// Root cause (verified against source, HEAD):
//   - Probes are attached keyed by podIdentifier = "<podName minus last '-' segment>@<ns>".
//     Pods named "<prefix>-<rand>" collapse to ONE podIdentifier "<prefix>@<ns>" and share
//     one program + maps + cached FDs on a node.
//   - A program RELOAD happens when a podIdentifier's set drains to ZERO (last pod's
//     DeleteBPFProbes closes FDs via UnPinMap + purges policyEndpointeBPFContext) and then a
//     NEW pod of that podIdentifier arrives (ProgFD==0 => loadBPFProgram => fresh FDs). FD
//     numbers are handed out lowest-free-first, so reloads recycle the same numbers.
//   - The cached map handle can then point at a recycled fd. UpdatePodStateEbpfMaps indexes
//     Maps[TC_INGRESS_POD_STATE_MAP] (single-value form) and writes via that cached FD without
//     re-deriving or invalidating on error, so the write hits the wrong object:
//         recycled to a non-map object  -> EINVAL ("invalid argument")   <-- this bug
//         closed/unallocated            -> EBADF  ("bad file descriptor")
//         recycled to a full hash map   -> E2BIG  ("argument list too long")
//   - The datapath fails CLOSED on a missing pod_state entry (tc.v4ingress.bpf.c:419,
//     `if (pst == NULL) return BPF_DROP`), so the whole podIdentifier INGRESS-blackholes until
//     a reload happens to fix it.
//
// CHURN SHAPE (matches the field report):
//   - A plateau never reproduces it: the FD is only closed when the set hits the LAST pod, so
//     a full set never triggers a close/reload. Reloads REQUIRE drain-to-zero then a new pod.
//   - The EINVAL flip is far likelier when MULTIPLE podIdentifiers churn concurrently so their
//     FD opens steal each other's just-freed numbers.
//   - ~15-20s pod lifetimes with a short (~1-6s) gap between drain and the next generation.
//
// KEY REPRO CHOICES (corrected from the earlier version of this test):
//   1. NO NetworkPolicy selects the churn pods. Verified in EnforceNpToPod: with no policy the
//      "else" branch writes pod_state (DEFAULT_ALLOW) for EVERY pod, maximizing writes against a
//      potentially stale handle. A selecting policy makes pods 2..N skip the write ("Pod shares
//      the eBPF firewall maps... No Map update required"), which REDUCES exposure. Probes still
//      attach: AttacheBPFProbes is called unconditionally at the top of EnforceNpToPod when the
//      cluster has ENABLE_NETWORK_POLICY=true (the prerequisite for this suite).
//   2. INGRESS oracle. The bug blackholes INGRESS, not egress. Each churn pod runs a TCP
//      listener and a TCP readiness probe (kubelet -> pod = ingress). A blackholed pod is
//      Running-but-never-Ready. We count Running && !Ready churn pods older than a grace period
//      as blackhole victims. (The previous canary probed egress and lived in a never-draining
//      podIdentifier, so it could not observe the bug on two counts.)
//
// Positive reproducer: PASSES when NEW pod_state write-failure lines appear during churn
// (baseline delta). Invert the final assertion for a post-fix regression guard.
//
// OS-agnostic (Bottlerocket + AL2023). Prerequisite: VPC CNI with ENABLE_NETWORK_POLICY=true.

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	blackholeChurnDuration = 30 * time.Minute
	blackholeGenSize       = 8                // pods per generation per podIdentifier
	blackholeGenLifetime   = 18 * time.Second // gen lives (long enough to attach+write+become Ready), then drain to 0
	blackholeGenGap        = 3 * time.Second  // empty window => next gen's first pod RELOADs
	blackholeScanInterval  = 15 * time.Second
	blackholeProbePort     = 8080
	// A healthy churn pod becomes Ready within a few seconds; anything Running-but-NotReady
	// older than this is treated as ingress-blackholed.
	blackholeReadyGrace = 8 * time.Second

	sdkLogPath = "/npalog/ebpf-sdk.log"
	npaLogPath = "/npalog/network-policy-agent.log"

	// Broad SDK-side signal (any stale-FD write failure errno).
	sdkPattern = "unable to (create/update|update) map|invalid argument|bad file descriptor|argument list too long"
	// Precise agent-side signature for THIS bug: the pod_state write failing.
	pstFailPattern = "Pod State Map update failed"
	closePattern   = "Found the Program and Map to delete|Deleting: Program" // FD close/unpin fired
	reloadPattern  = "Prog Load Succeeded for (ingress|egress)"              // a program reload happened
)

// Distinct podIdentifiers ("<prefix>-<rand>" -> "<prefix>@<ns>") churned in parallel so their
// FD opens steal each other's just-freed numbers (the EINVAL flip driver).
var blackholePrefixes = []string{"churn-a", "churn-b", "churn-c", "churn-d"}

var _ = Describe("Pod-state stale-FD blackhole under same-podIdentifier churn", Ordered, func() {

	It("reproduces EINVAL pod_state write failures + ingress blackhole via multi-podIdentifier drain-to-zero reload churn", func() {
		By("Selecting a single linux worker node to concentrate all churn onto")
		nodes, err := getReproNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", 1))
		node := nodes[0]
		GinkgoWriter.Printf("Target node: %s (OS: %s)\n", node.Name, node.Status.NodeInfo.OSImage)

		// NOTE: intentionally NO NetworkPolicy. Leaving the churn pods unselected drives the
		// no-policy branch in EnforceNpToPod, which writes pod_state for EVERY pod (not just the
		// first), maximizing writes against a stale cached FD. Probes still attach unconditionally.

		By("Deploying a log-reader pod that hostPath-mounts /var/log/aws-routed-eni")
		readerName := fmt.Sprintf("blackhole-logreader-%s", node.Name)
		reader := buildLogReaderPod(readerName, node.Name)
		_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, reader, 2*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { _ = fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, reader) })
		DeferCleanup(cleanupChurnPods)

		By("Recording baseline counts before churn (only NEW failures count as a repro)")
		sdkBaseline := grepCount(readerName, sdkLogPath, sdkPattern)
		pstBaseline := grepCount(readerName, npaLogPath, pstFailPattern)
		reloadBaseline := grepCount(readerName, npaLogPath, reloadPattern)
		closeBaseline := grepCount(readerName, npaLogPath, closePattern)
		GinkgoWriter.Printf("Baseline: sdkErr=%d pstFail=%d reloads=%d closes=%d\n",
			sdkBaseline, pstBaseline, reloadBaseline, closeBaseline)

		By(fmt.Sprintf("Churning %d unselected podIdentifiers, gen=%d, life=%v, gap=%v, for up to %v",
			len(blackholePrefixes), blackholeGenSize, blackholeGenLifetime, blackholeGenGap, blackholeChurnDuration))
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var created int64
		for pi, prefix := range blackholePrefixes {
			wg.Add(1)
			go func(prefix string, idx int) {
				defer GinkgoRecover()
				defer wg.Done()
				// Stagger podIdentifiers so their drains/reloads interleave (FD cross-contamination).
				select {
				case <-stop:
					return
				case <-time.After(time.Duration(idx) * blackholeGenGap):
				}
				for {
					select {
					case <-stop:
						return
					default:
					}
					gen := make([]*v1.Pod, 0, blackholeGenSize)
					for i := 0; i < blackholeGenSize; i++ {
						p := buildChurnPod(fmt.Sprintf("%s-%s", prefix, randSuffix(6)), node.Name, namespace)
						_ = fw.K8sClient.Create(ctx, p)
						atomic.AddInt64(&created, 1)
						gen = append(gen, p)
					}
					select {
					case <-stop:
						deleteAll(gen)
						return
					case <-time.After(blackholeGenLifetime):
					}
					deleteAll(gen) // drain to zero => close + purge => next gen reloads
					select {
					case <-stop:
						return
					case <-time.After(blackholeGenGap):
					}
				}
			}(prefix, pi)
		}

		By("Watching for NEW pod_state write failures and sustained ingress-blackholed churn pods")
		start := time.Now()
		deadline := start.Add(blackholeChurnDuration)
		found := false
		logRepro := false
		blackholeRepro := false
		consecutiveBlackhole := 0
		maxBlackholed := 0
		var firstHit string
		for time.Now().Before(deadline) {
			time.Sleep(blackholeScanInterval)

			newSdk := grepCount(readerName, sdkLogPath, sdkPattern) - sdkBaseline
			newPst := grepCount(readerName, npaLogPath, pstFailPattern) - pstBaseline
			reloadCur := grepCount(readerName, npaLogPath, reloadPattern) - reloadBaseline
			closeCur := grepCount(readerName, npaLogPath, closePattern) - closeBaseline
			blackholed := countBlackholedChurnPods(blackholeReadyGrace)
			if blackholed > maxBlackholed {
				maxBlackholed = blackholed
			}
			// Require the blackhole to persist across consecutive scans so a single-scan blip
			// (e.g. a pod momentarily NotReady) does not count. Terminating pods are already
			// excluded in countBlackholedChurnPods.
			if blackholed > 0 {
				consecutiveBlackhole++
			} else {
				consecutiveBlackhole = 0
			}

			GinkgoWriter.Printf("[t=%s] created=%d newPstFail=%d newSdkErr=%d reloads=%d closes=%d ingressBlackholed=%d(x%d)\n",
				time.Since(start).Truncate(time.Second), atomic.LoadInt64(&created),
				newPst, newSdk, reloadCur, closeCur, blackholed, consecutiveBlackhole)

			logRepro = newPst > 0 || newSdk > 0
			// Two consecutive scans of live, non-terminating, NotReady pods = a real, sustained
			// ingress blackhole. This also catches the SILENT variant (recycled fd lands on a
			// valid map => write "succeeds", no error logged, but the real pod_state map stays
			// empty and the datapath drops) that the log signature cannot see.
			blackholeRepro = consecutiveBlackhole >= 2

			if logRepro || blackholeRepro {
				found = true
				n := newPst
				if newSdk > n {
					n = newSdk
				}
				firstHit = lastN(grepLog(readerName, npaLogPath, pstFailPattern), n+2) + "\n---\n" +
					lastN(grepLog(readerName, sdkLogPath, sdkPattern), n+2)
				break
			}
		}

		By("Stopping churn")
		close(stop)
		wg.Wait()

		reloads := grepCount(readerName, npaLogPath, reloadPattern) - reloadBaseline
		closes := grepCount(readerName, npaLogPath, closePattern) - closeBaseline
		GinkgoWriter.Printf("Totals during churn: reloads=%d closes=%d created=%d maxIngressBlackholed=%d logRepro=%t blackholeRepro=%t\n",
			reloads, closes, atomic.LoadInt64(&created), maxBlackholed, logRepro, blackholeRepro)
		if reloads == 0 || closes == 0 {
			GinkgoWriter.Printf("WARNING: reloads=%d closes=%d -> the reload/recycle cycle was NOT exercised "+
				"(set not draining to zero, or probes not attaching / NP disabled). No shaping of writes can help "+
				"until these climb. Verify ENABLE_NETWORK_POLICY=true on the cluster.\n", reloads, closes)
		}
		if found {
			if logRepro {
				GinkgoWriter.Printf("REPRODUCED (logged) stale-FD blackhole. NEW pod_state / SDK write-failure lines:\n%s\n", firstHit)
			} else {
				GinkgoWriter.Printf("REPRODUCED (silent) stale-FD blackhole: churn pods stayed Running-but-NotReady across "+
					"consecutive scans with NO write-failure log line — consistent with a recycled fd landing on a valid "+
					"map (write succeeds into the wrong map; real pod_state stays empty; datapath drops).\n")
			}
			GinkgoWriter.Printf("Confirm with: 'ID of map to update: ID: N' in the agent log vs the live pinned map id "+
				"(aws-eks-na-cli ebpf loaded-ebpfdata); N != live id proves a stale/recycled handle.\n")
		}

		Expect(found).To(BeTrue(),
			"no pod_state write failures AND no sustained ingress blackhole in %v (reloads=%d, closes=%d, "+
				"maxIngressBlackholed=%d). reloads/closes>0 means the reload/recycle cycle ran but the µs fd-recycle "+
				"window did not land on a wrong object — expected: this race is secondary-event driven (SDK double-close "+
				"per aws-ebpf-sdk-go#145, or a concurrent close racing a cached write) and e2e churn cannot reliably "+
				"drive it. The deterministic guard is the white-box test "+
				"TestUpdatePodStateEbpfMaps_StaleFDNotRecovered.",
			blackholeChurnDuration, reloads, closes, maxBlackholed)
	})
})

// deleteAll issues fast (grace 0) deletes so the set drops to zero sharply.
func deleteAll(pods []*v1.Pod) {
	for _, p := range pods {
		_ = fw.K8sClient.Delete(ctx, p, client.GracePeriodSeconds(0))
	}
}

// cleanupChurnPods force-deletes any churn pods left behind at the end of the run.
func cleanupChurnPods() {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", "churn-pod")
	if err != nil {
		return
	}
	for i := range pods {
		_ = fw.K8sClient.Delete(ctx, &pods[i], client.GracePeriodSeconds(0))
	}
}

func getReproNodes() ([]v1.Node, error) {
	nodeList := &v1.NodeList{}
	if err := fw.K8sClient.List(ctx, nodeList, client.MatchingLabels{"kubernetes.io/os": "linux"}); err != nil {
		return nil, err
	}
	return nodeList.Items, nil
}

func buildLogReaderPod(name, nodeName string) *v1.Pod {
	dirOrCreate := v1.HostPathDirectoryOrCreate
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name:         "logreader",
				Image:        "public.ecr.aws/docker/library/busybox:1.36",
				Command:      []string{"sleep", "100000"},
				VolumeMounts: []v1.VolumeMount{{Name: "npalog", MountPath: "/npalog", ReadOnly: true}},
			}},
			Volumes: []v1.Volume{{
				Name: "npalog",
				VolumeSource: v1.VolumeSource{
					HostPath: &v1.HostPathVolumeSource{Path: "/var/log/aws-routed-eni", Type: &dirOrCreate},
				},
			}},
		},
	}
}

// buildChurnPod builds a short-lived pod that opens a TCP listener and carries a TCP readiness
// probe. The readiness probe is kubelet -> pod (INGRESS), so a pod whose podIdentifier is
// ingress-blackholed (missing pod_state entry => BPF_DROP) stays Running-but-NotReady.
func buildChurnPod(name, nodeName, ns string) *v1.Pod {
	grace := int64(0)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{"app": "churn-pod"},
		},
		Spec: v1.PodSpec{
			NodeName:                      nodeName,
			RestartPolicy:                 v1.RestartPolicyNever,
			TerminationGracePeriodSeconds: &grace,
			Containers: []v1.Container{{
				Name:    "churn",
				Image:   "public.ecr.aws/docker/library/busybox:1.36",
				Command: []string{"httpd", "-f", "-p", strconv.Itoa(blackholeProbePort)},
				Ports:   []v1.ContainerPort{{ContainerPort: int32(blackholeProbePort)}},
				ReadinessProbe: &v1.Probe{
					ProbeHandler: v1.ProbeHandler{
						TCPSocket: &v1.TCPSocketAction{Port: intstr.FromInt(blackholeProbePort)},
					},
					InitialDelaySeconds: 1,
					PeriodSeconds:       2,
					TimeoutSeconds:      2,
					FailureThreshold:    2,
					SuccessThreshold:    1,
				},
				Resources: v1.ResourceRequirements{
					Requests: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("1m"),
						v1.ResourceMemory: resource.MustParse("8Mi"),
					},
				},
			}},
		},
	}
}

// countBlackholedChurnPods counts churn pods that are Running but have been NotReady for longer
// than minAge — i.e. their ingress readiness probe never succeeded, the signature of an
// ingress blackhole at birth.
//
// Terminating pods (DeletionTimestamp set) are excluded: during a drain-to-zero mass-delete a
// pod is briefly Running+NotReady with an old StartTime, which would otherwise be counted as a
// false-positive "blackhole". Only live, non-terminating pods count.
func countBlackholedChurnPods(minAge time.Duration) int {
	pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, "app", "churn-pod")
	if err != nil {
		return 0
	}
	n := 0
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != v1.PodRunning {
			continue
		}
		if p.DeletionTimestamp != nil {
			continue // terminating: readiness flips false on teardown, not a blackhole
		}
		if isChurnPodReady(p) {
			continue
		}
		if p.Status.StartTime != nil && time.Since(p.Status.StartTime.Time) > minAge {
			n++
		}
	}
	return n
}

func isChurnPodReady(p *v1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}

func grepLog(readerPodName, path, pattern string) string {
	out, err := fw.PodManager.ExecInPod(namespace, readerPodName, []string{
		"sh", "-c",
		fmt.Sprintf("grep -E '%s' %s 2>/dev/null | tail -n 50", pattern, path),
	})
	if err != nil {
		return ""
	}
	return out
}

func grepCount(readerPodName, path, pattern string) int {
	out, err := fw.PodManager.ExecInPod(namespace, readerPodName, []string{
		"sh", "-c",
		fmt.Sprintf("grep -Ec '%s' %s 2>/dev/null | head -n1", pattern, path),
	})
	if err != nil {
		return 0
	}
	n, e := strconv.Atoi(strings.TrimSpace(out))
	if e != nil {
		return 0
	}
	return n
}

func lastN(s string, n int) string {
	if n < 1 {
		n = 1
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var blackholeLetters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

func randSuffix(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = blackholeLetters[rand.Intn(len(blackholeLetters))]
	}
	return string(b)
}
