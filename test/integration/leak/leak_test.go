package leak

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// churnCycles is the number of churn-then-drain iterations. A leak is
	// detected as a resource baseline that fails to recover after drain, and/or
	// that drifts upward cycle-over-cycle — so more than one cycle is required.
	churnCycles = 3

	// jobsPerCycle is the number of DISTINCT single-completion Jobs launched per
	// cycle. Each Job has a unique name, which (because GetPodIdentifier strips
	// the last "-" segment of the pod name) yields a UNIQUE podIdentifier per
	// pod and therefore a unique, un-shared eBPF program. This defeats the
	// "sibling rescue" that masked the leak when 100 pods shared one identifier:
	// with no sibling to reclaim it, a single partial-attach failure leaves a
	// durable orphaned program + FDs.
	jobsPerCycle = 80

	churnLabelKey = "app"
	churnLabelVal = "churn-pod"

	drainTimeout     = 6 * time.Minute
	settleAfterDrain = 90 * time.Second // allow CNI DEL + reconcile + prog cleanup to settle
	inspectorTimeout = 3 * time.Minute

	// fdTolerance absorbs benign, transient reconcile state. Any real leak grows
	// without bound across cycles and blows well past this.
	fdTolerance = 6

	inspectorImage = "public.ecr.aws/amazonlinux/amazonlinux:2023"
	churnImage     = "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal"
)

// fdScanScript finds the network policy agent process (ENTRYPOINT "/controller")
// via the shared host PID namespace and reports its open-FD counts. BPF_FD counts
// only bpf-prog / bpf-map file descriptors, which is the resource this leak
// actually exhausts, so it is the most direct black-box signal.
const fdScanScript = `
PID=""
for c in /proc/[0-9]*/cmdline; do
  first=$(tr '\0' '\n' < "$c" 2>/dev/null | head -n1)
  if [ "$first" = "/controller" ]; then
    PID=$(echo "$c" | sed 's#/proc/##; s#/cmdline##')
    break
  fi
done
if [ -z "$PID" ]; then echo "PID_NOT_FOUND"; exit 0; fi
TOTAL=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
BPF=$(ls -l /proc/$PID/fd 2>/dev/null | grep -c 'bpf-prog\|bpf-map')
echo "PID=$PID TOTAL_FD=$TOTAL BPF_FD=$BPF"
`

type nodeBaseline struct {
	bpfFD     int
	churnPins int
}

var _ = Describe("BPF Probe Leak Under Pod Churn", Ordered, func() {
	var (
		networkPolicy     *network.NetworkPolicy
		defaultDenyPolicy *network.NetworkPolicy
		workerNodes       []v1.Node
		inspectorByNode   = map[string]string{} // nodeName -> inspector pod name
	)

	It("should not leak BPF programs/FDs across repeated pod churn cycles", func() {
		By("Getting worker nodes and labeling them for churn scheduling")
		var err error
		workerNodes, err = getWorkerNodes()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(workerNodes)).To(BeNumerically(">=", 1))
		lo.ForEach(workerNodes, func(node v1.Node, _ int) {
			node.Labels["test-node"] = "true"
			Expect(fw.K8sClient.Update(ctx, &node)).ToNot(HaveOccurred())
		})

		By("Applying default-deny + churn-pod network policies to force probe attachment")
		defaultDenyPolicy = buildDefaultDenyNetworkPolicy()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, defaultDenyPolicy)).ToNot(HaveOccurred())

		networkPolicy = buildChurnNetworkPolicy()
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).ToNot(HaveOccurred())

		By("Deploying a privileged hostPID inspector pod on each node")
		for _, node := range workerNodes {
			name := fmt.Sprintf("leak-inspector-%s", randSuffix(6))
			pod := buildInspectorPod(name, node.Name)
			_, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, inspectorTimeout)
			Expect(err).ToNot(HaveOccurred())
			inspectorByNode[node.Name] = name
			p := pod
			DeferCleanup(func() { fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, p) })
		}

		By("Recording resource baseline before any churn")
		baseline := map[string]nodeBaseline{}
		for node, insp := range inspectorByNode {
			bpfFD := readControllerBpfFdCount(insp)
			pins := countChurnPins(insp)
			baseline[node] = nodeBaseline{bpfFD: bpfFD, churnPins: pins}
			By(fmt.Sprintf("baseline node=%s bpfFD=%d churnPins=%d", node, bpfFD, pins))
			// No churn workload has run yet, so there must be zero churn pins.
			Expect(pins).To(Equal(0), "unexpected pre-existing churn artifacts on %s", node)
		}

		for cycle := 1; cycle <= churnCycles; cycle++ {
			By(fmt.Sprintf("=== Churn cycle %d/%d: launching %d unique-identifier Jobs ===",
				cycle, churnCycles, jobsPerCycle))

			jobs := make([]*batchv1.Job, 0, jobsPerCycle)
			for i := 0; i < jobsPerCycle; i++ {
				// Unique job name -> unique podIdentifier (no sibling rescue).
				jobName := fmt.Sprintf("churn-c%d-%d-%s", cycle, i, randSuffix(5))
				// Vary the lifetime (0/1/2s) so some pods are torn down mid-attach
				// (partial-attach race) and some right after — maximizing the
				// probability of hitting the leak window.
				job := buildChurnLeakJob(jobName, i%3)
				Expect(fw.K8sClient.Create(ctx, job)).ToNot(HaveOccurred())
				jobs = append(jobs, job)
			}

			By("Waiting for churn pods to drain")
			waitForChurnDrain()

			By("Deleting churn Jobs and letting cleanup settle")
			for _, j := range jobs {
				bg := metav1.DeletePropagationBackground
				_ = fw.K8sClient.Delete(ctx, j, &client.DeleteOptions{PropagationPolicy: &bg})
			}
			waitForChurnDrain()
			time.Sleep(settleAfterDrain)

			By(fmt.Sprintf("Sampling resources after cycle %d drain", cycle))
			for node, insp := range inspectorByNode {
				bpfFD := readControllerBpfFdCount(insp)
				pins := countChurnPins(insp)
				base := baseline[node]
				By(fmt.Sprintf("cycle=%d node=%s bpfFD=%d (baseline %d) churnPins=%d",
					cycle, node, bpfFD, base.bpfFD, pins))

				// Precise signal: with unique identifiers there is no sibling to
				// reclaim a leaked program, so ANY surviving churn pin after a
				// full drain is a genuine leak.
				Expect(pins).To(Equal(0),
					"LEAK: %d orphaned churn-pod BPF program(s) still pinned on node %s after cycle %d drain",
					pins, node, cycle)

				// Direct FD signal: the agent's bpf-prog/bpf-map FD count must
				// return to (approximately) its pre-churn baseline once pods drain.
				Expect(bpfFD).To(BeNumerically("<=", base.bpfFD+fdTolerance),
					"LEAK: agent BPF FD count on node %s did not recover after cycle %d "+
						"(got %d, baseline %d, tolerance %d)",
					node, cycle, bpfFD, base.bpfFD, fdTolerance)
			}
		}
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		if defaultDenyPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, defaultDenyPolicy)
		}
		lo.ForEach(workerNodes, func(node v1.Node, _ int) {
			delete(node.Labels, "test-node")
			fw.K8sClient.Update(ctx, &node)
		})
	})
})

func buildDefaultDenyNetworkPolicy() *network.NetworkPolicy {
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("default-deny-all").
		SetPolicyType(true, true).
		Build()
}

func buildChurnNetworkPolicy() *network.NetworkPolicy {
	// Deny all ingress and egress for churn pods — forces eBPF probe attachment.
	return manifest.NewNetworkPolicyBuilder().
		Namespace(namespace).
		Name("churn-pod-policy").
		PodSelector(churnLabelKey, churnLabelVal).
		SetPolicyType(true, true).
		Build()
}

// getWorkerNodes returns the Linux AL2023 worker nodes used for churn.
func getWorkerNodes() ([]v1.Node, error) {
	nodeList := &v1.NodeList{}
	err := fw.K8sClient.List(ctx, nodeList, client.MatchingLabels{
		"kubernetes.io/os": "linux",
	})
	if err != nil {
		return nil, err
	}
	return lo.Filter(nodeList.Items, func(node v1.Node, index int) bool {
		return strings.Contains(node.Status.NodeInfo.OSImage, "Amazon Linux 2023")
	}), nil
}

// buildChurnLeakJob builds a single-completion Job whose pod dies quickly. The
// unique job name yields a unique podIdentifier (no sibling rescue). sleepSeconds
// varies the pod lifetime to spread coverage across the attach window.
func buildChurnLeakJob(name string, sleepSeconds int) *batchv1.Job {
	completions := int32(1)
	parallelism := int32(1)
	backoffLimit := int32(0)
	ttl := int32(15)
	grace := int64(0)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			Completions:             &completions,
			Parallelism:             &parallelism,
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttl,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{churnLabelKey: churnLabelVal},
				},
				Spec: v1.PodSpec{
					NodeSelector:                  map[string]string{"test-node": "true"},
					RestartPolicy:                 v1.RestartPolicyNever,
					TerminationGracePeriodSeconds: &grace,
					Containers: []v1.Container{
						{
							Name:    "churn",
							Image:   churnImage,
							Command: []string{"sleep", strconv.Itoa(sleepSeconds)},
							Resources: v1.ResourceRequirements{
								Requests: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("1m"),
									v1.ResourceMemory: resource.MustParse("4Mi"),
								},
							},
						},
					},
				},
			},
		},
	}
}

// buildInspectorPod builds a long-lived privileged pod that shares the host PID
// namespace and mounts the host root, so it can read /proc/<agent-pid>/fd and run
// the on-host aws-eks-na-cli via chroot.
func buildInspectorPod(name, nodeName string) *v1.Pod {
	privileged := true
	hostPathDir := v1.HostPathDirectory
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName:      nodeName,
			HostPID:       true,
			HostNetwork:   true,
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{
				{
					Name:            "inspector",
					Image:           inspectorImage,
					Command:         []string{"sleep", "7200"},
					SecurityContext: &v1.SecurityContext{Privileged: &privileged},
					VolumeMounts: []v1.VolumeMount{
						{Name: "host-root", MountPath: "/host", ReadOnly: true},
					},
				},
			},
			Volumes: []v1.Volume{
				{
					Name: "host-root",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{Path: "/", Type: &hostPathDir},
					},
				},
			},
		},
	}
}

// readControllerBpfFdCount execs the FD scan in the inspector pod and returns the
// agent's bpf-prog/bpf-map FD count.
func readControllerBpfFdCount(inspectorPod string) int {
	out, err := fw.PodManager.ExecInPod(namespace, inspectorPod, []string{"sh", "-c", fdScanScript})
	Expect(err).ToNot(HaveOccurred())
	Expect(out).ToNot(ContainSubstring("PID_NOT_FOUND"),
		"could not locate /controller agent process from inspector pod")
	return parseIntToken(out, "BPF_FD=")
}

// countChurnPins returns the number of pinned BPF programs whose pin path belongs
// to a churn pod (identifier prefixed with "churn-c"). With unique identifiers a
// nonzero count after drain is a genuine orphaned program.
func countChurnPins(inspectorPod string) int {
	out, err := fw.PodManager.ExecInPod(namespace, inspectorPod,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred())

	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "PinPath:") && strings.Contains(line, "churn-c") {
			count++
		}
	}
	return count
}

// waitForChurnDrain blocks until no churn-pod remains in the namespace.
func waitForChurnDrain() {
	Eventually(func() int {
		pods, err := fw.PodManager.GetPodsWithLabel(ctx, namespace, churnLabelKey, churnLabelVal)
		if err != nil {
			return -1
		}
		return len(pods)
	}, drainTimeout, 5*time.Second).Should(Equal(0), "churn pods failed to drain")
}

// parseIntToken extracts the integer following `token` (e.g. "BPF_FD=") in s.
func parseIntToken(s, token string) int {
	idx := strings.Index(s, token)
	Expect(idx).To(BeNumerically(">=", 0), "token %q not found in output: %s", token, s)
	rest := s[idx+len(token):]
	end := strings.IndexAny(rest, " \n\t")
	if end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest))
	Expect(err).ToNot(HaveOccurred(), "failed to parse int from %q", rest)
	return n
}
