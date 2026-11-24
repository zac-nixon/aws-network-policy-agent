package controllers

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Policy enforcement runs in two stages.
//
// Stage 1 is the (slice, parent) reconcile. It runs on a single worker, recomputes what the
// parent policy selects from its live slices, records that in the reconciler's maps, and queues
// every pod identifier whose eBPF maps that may have changed. It never touches eBPF state.
//
// Stage 2 programs one pod identifier at a time: it attaches probes for the identifier's
// selected pods on this node, then rewrites the identifier's maps from the recorded state and
// the informer cache as they are when the pass runs. The queue never hands one identifier to two
// workers at once, and reprocesses an identifier queued while it was being processed, so the
// last pass for an identifier always reads the newest state. A failed pass is retried with
// backoff until one succeeds.

const (
	policyEndpointProgrammerName        = "policyendpoint-programmer"
	clusterPolicyEndpointProgrammerName = "clusterpolicyendpoint-programmer"

	programmingRetryBaseDelay = 5 * time.Millisecond
	programmingRetryMaxDelay  = 30 * time.Second

	maxPendingChangesPerIdentifier = 64
)

// newProgrammingQueue returns a stage-2 queue. It exists from construction, so adding to it never
// blocks, including from the CNI RPC path before the manager starts.
func newProgrammingQueue(name string) priorityqueue.PriorityQueue[string] {
	return priorityqueue.New[string](name, func(o *priorityqueue.Opts[string]) {
		o.RateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[string](
			programmingRetryBaseDelay, programmingRetryMaxDelay)
	})
}

// setupProgrammer registers the stage-2 controller that runs program on the identifiers in queue.
func setupProgrammer(mgr ctrl.Manager, name string, queue priorityqueue.PriorityQueue[string], workers int,
	program func(context.Context, string) error) error {
	_, err := controller.NewTyped[string](name, mgr, controller.TypedOptions[string]{
		Reconciler: reconcile.TypedFunc[string](func(ctx context.Context, podIdentifier string) (reconcile.Result, error) {
			return reconcile.Result{}, program(ctx, podIdentifier)
		}),
		MaxConcurrentReconciles: workers,
		NewQueue: func(string, workqueue.TypedRateLimiter[string]) workqueue.TypedRateLimitingInterface[string] {
			return queue
		},
	})
	return err
}

// identifiersToProgram returns the identifiers a policy's reconcile must queue: the ones it
// selects pods of on this node, and the ones whose pods here it selected before, so a pod it
// stopped selecting is reprogrammed.
//
// An identifier the policy selects only on other nodes is not queued, even though the policy's
// rules reach this node's replicas through the shared maps. Queueing it when the policy stops
// selecting it would reset a new pod here to the baseline in the interval during a rollout
// when NPC has dropped the last old replica and not yet listed the new one, a pod that CNI ADD
// programmed with the policy's rules. This node's rules for such an identifier change only
// when something else reprograms it.
//
// Only identifiers with programs on this node are queued, plus ones with selected pods here,
// whose programming pass attaches them.
func identifiersToProgram(ebpfClient ebpf.BpfClient, localPods, priorLocalPods map[string][]npatypes.Pod) []string {
	queued := make(map[string]bool, len(localPods)+len(priorLocalPods))
	var podIdentifiers []string
	consider := func(podIdentifier string) {
		if queued[podIdentifier] {
			return
		}
		queued[podIdentifier] = true
		if len(localPods[podIdentifier]) > 0 || ebpfClient.HasBPFContext(podIdentifier) {
			podIdentifiers = append(podIdentifiers, podIdentifier)
		}
	}
	for podIdentifier := range localPods {
		consider(podIdentifier)
	}
	for podIdentifier := range priorLocalPods {
		consider(podIdentifier)
	}
	slices.Sort(podIdentifiers)
	return podIdentifiers
}

func queueIdentifiers(queue priorityqueue.PriorityQueue[string], podIdentifiers []string) {
	for _, podIdentifier := range podIdentifiers {
		queue.Add(podIdentifier)
	}
}

// localPodsOf returns the pods of podIdentifier on this node that the given policies select,
// from each policy's entry in localPodsByPolicy (map[string][]npatypes.Pod per policy key).
func localPodsOf(localPodsByPolicy *sync.Map, podIdentifier string, policyKeys []string) []npatypes.Pod {
	var pods []npatypes.Pod
	for _, key := range lo.Uniq(policyKeys) {
		if v, ok := localPodsByPolicy.Load(key); ok {
			pods = append(pods, v.(map[string][]npatypes.Pod)[podIdentifier]...)
		}
	}
	return uniquePods(pods)
}

// uniquePods dedupes on identity rather than the whole struct: a StatefulSet pod keeps its name
// across recreation but not its address, so two slices can list it with different IPs.
func uniquePods(pods []npatypes.Pod) []npatypes.Pod {
	return lo.UniqBy(pods, func(pod npatypes.Pod) types.NamespacedName { return pod.NamespacedName })
}

// programmingPass is what one programming pass for an identifier did.
type programmingPass struct {
	// wrote is true when the identifier's maps were written.
	wrote bool
	// skipped is the number of pods whose attach cannot be retried into success.
	skipped int
}

// changeTriggerTime returns the last-change-trigger-time annotation NPC set on a policy endpoint,
// if it is newer than startedAt and was not already consumed for req, and marks it consumed.
// Each value is consumed once, so a resync or relist of an unchanged endpoint never re-observes it.
func changeTriggerTime(annotations map[string]string, startedAt time.Time, req EndpointRequest,
	consumed *sync.Map) (time.Time, bool) {
	triggerTimeStr := annotations[LastChangeTriggerTimeAnnotation]
	if triggerTimeStr == "" {
		return time.Time{}, false
	}
	triggerTime, err := time.Parse(time.RFC3339Nano, triggerTimeStr)
	if err != nil {
		log().Debugf("Failed to parse %s annotation: %v", LastChangeTriggerTimeAnnotation, err)
		return time.Time{}, false
	}
	if !triggerTime.After(startedAt) {
		return time.Time{}, false
	}
	if prev, ok := consumed.Load(req); ok && prev.(string) == triggerTimeStr {
		return time.Time{}, false
	}
	consumed.Store(req, triggerTimeStr)
	return triggerTime, true
}

// programmingLatencyTracker turns a policy change's trigger time into one E2E programming
// latency sample, taken once every identifier the change queued on this node has been
// programmed, retries included. A change that queued nothing, or whose identifiers all turned
// out to have nothing on this node, produces no sample.
type programmingLatencyTracker struct {
	histogram prometheus.Observer
	now       func() time.Time

	mu      sync.Mutex
	pending map[string][]*pendingChange
}

type pendingChange struct {
	triggeredAt time.Time
	// identifiers not yet programmed
	remaining int
	// whether some identifier's pass wrote maps
	wrote bool
}

func newProgrammingLatencyTracker(histogram prometheus.Observer) *programmingLatencyTracker {
	return &programmingLatencyTracker{histogram: histogram, now: time.Now, pending: map[string][]*pendingChange{}}
}

// track registers a change that queued podIdentifiers. It must run before they are queued, so
// a pass cannot land them before the change is waiting on it.
func (t *programmingLatencyTracker) track(triggeredAt time.Time, podIdentifiers []string) {
	podIdentifiers = lo.Uniq(podIdentifiers)
	if len(podIdentifiers) == 0 {
		return
	}
	change := &pendingChange{triggeredAt: triggeredAt, remaining: len(podIdentifiers)}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, podIdentifier := range podIdentifiers {
		pending := append(t.pending[podIdentifier], change)
		// An identifier whose pods never attach never lands its changes; bound what it holds.
		// Dropping the oldest loses only its sample: no other identifier can land it alone.
		if len(pending) > maxPendingChangesPerIdentifier {
			pending = slices.Delete(pending, 0, len(pending)-maxPendingChangesPerIdentifier)
		}
		t.pending[podIdentifier] = pending
	}
}

// begin returns the changes a pass for podIdentifier starting now will land if it succeeds.
// Changes tracked after this point wait for the next pass, which their queueing guarantees.
func (t *programmingLatencyTracker) begin(podIdentifier string) []*pendingChange {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.pending[podIdentifier])
}

// finish records that a successful pass for podIdentifier landed the changes begin returned.
func (t *programmingLatencyTracker) finish(podIdentifier string, landed []*pendingChange, wrote bool) {
	if len(landed) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	remaining := slices.DeleteFunc(t.pending[podIdentifier], func(c *pendingChange) bool {
		return slices.Contains(landed, c)
	})
	if len(remaining) == 0 {
		delete(t.pending, podIdentifier)
	} else {
		t.pending[podIdentifier] = remaining
	}
	for _, change := range landed {
		change.wrote = change.wrote || wrote
		change.remaining--
		if change.remaining > 0 || !change.wrote {
			continue
		}
		latency := t.now().Sub(change.triggeredAt).Seconds()
		if latency < 0 {
			// Clock skew between NPC (control plane) and this node
			log().Debugf("Skipping negative E2E policy programming latency %.3fs", latency)
			continue
		}
		t.histogram.Observe(latency)
	}
}
