# Two-stage reconcile for policy enforcement

**Status:** prototype on `feat/two-stage-reconcile` (one local commit on `main`); the harness is not in the tree and nothing has run on a cluster.
**Ask:** continue toward merge with one stage-1 and one stage-2 worker per controller. `--max-concurrent-reconciles` (inert today; one flag for both controllers) sets the stage-2 count; its default should change from 3 to 1.

## Problem
NPC (the network policy controller) splits each policy into slices naming a parent policy. Replicas of a workload share a **pod identifier** (namespace plus pod name minus its last segment) and, on a node, one pair of eBPF rule maps. Each controller runs one worker on `(slice, parent)`, but each reconcile rewrites the full rule set of every local identifier the parent selects: a 30-slice edit rewrites each identifier 30 times. More workers are unsafe, since concurrent reconciles can leave a pod with rules but allow-all state, or the reverse.

## Design
- **Stage 1** (the existing queue, one worker) never writes eBPF state. It recomputes the parent from its live slices and queues the identifiers it selects pods of on this node, now or before.
- **Stage 2** (a new queue keyed by pod identifier, N workers) attaches probes and writes the union of the rules of the slices selecting the identifier, or the baseline if none (allow-all; deny in strict mode). Failures retry with backoff.
- Probe load seeds `pod_state` (the per-pod flag the probe reads) with the baseline, since the probe drops everything while it is missing.

## Results
Harness modelled on `awslbc-loadtest` (29.5k pods, 360 local identifiers) with a fake BPF client running the real rule computation; median of 3. Wall time, `main` vs this branch:

| Scenario | Today | 1 worker | 2 workers |
|---|---:|---:|---:|
| Cold start | 120 s | 6.6 s | 4.0 s |
| Pod churn | 96.8 s | 4.2 s | 2.5 s |
| Large-policy edit | 90.8 s | 3.6 s | 2.2 s |
| Edit in every namespace | 6.3 s | 6.5 s | 3.6 s |
| Cluster-policy pod churn | 85.0 s | 1.5 s | 1.4 s |

- **Coalescing (batching repeated writes to an identifier) is the win:** rule-map writes per identifier fall from 6.7–30 to about 1.0 (cluster policies: 77 to under 4). The edit in every namespace has nothing to coalesce. The fake client has no kernel cost, and kernel-visible entry writes fall only 9–12%, so real speedups will be smaller.
- **A second worker** is 1.6–1.8× faster for network policies for +3–16% CPU, but 1.1–1.25× for cluster policies (stage 1 alone is ~1.1 s of the burst) for +25–35%. Hence the default of 1.
- **Beyond bursts:** an isolated change costs ~0.65 ms either way. Today's code builds a backlog at 10 events/s and saturates at 30/s; one worker still drains at 100/s. With 10% of identifiers failing, healthy ones converge 16–23× faster. Wall time grows with cluster size as n^2.3 today (1×–3×, one run) against n^1.2–1.3 here.

## Risks and behaviour changes
- **Seed:** the CNI handler is unchanged but calls the seeding attach, so a new pod is allow-all (standard mode) instead of drop-all between attach and its first write.
- **Rollout window:** NPC can drop a workload's last old replica from a policy before listing the new pod, so the identifier gets the baseline (unenforced in standard mode, dropped in strict) until it does. This is today's behaviour, unchanged with one worker; with two workers and a backlog it occurred in 8–9 of 9 replays against 0 of 9 today. When the policy had selected only other nodes' replicas the identifier is not reprogrammed, as today (also for edits and new policies), so the new pod keeps the policy's rules. Closing both needs `podSelector` matching (PolicyEndpoints only).
- **`isDeleteFlow` removed:** deleting a slice used to drop the parent's rules for local pods even when replicas elsewhere were still selected; now they stay, which can over-enforce for pod-specific selectors (StatefulSets).
- **Metrics:** `awsnodeagent_policy_setup_latency_ms` and `_teardown_latency_ms` now measure stage 1 only; two new controllers add queue metrics. PRs #764 and #760 touch the same paths.

## Before merge
- **Startup:** hold stage 2 until stage 1 has reconciled the initial list, or after a restart a pass writes only the policies seen so far and rules of policies deleted while down stay applied.
- **Fresh load:** also queue the other controller, or a cluster-policy Deny can stay missing; detach filters on attach rollback.
- **Defaults and tests:** flag default and a debounce; default-deny, cluster-policy stress and strict-mode tests; upgrade/downgrade and cluster validation.
