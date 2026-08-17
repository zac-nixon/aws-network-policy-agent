package ebpf

// Concurrency tests validating race-condition findings in the eBPF client.
//
// NOTE ON PLATFORM: pkg/ebpf only builds on Linux (the eBPF SDK pulls in
// unix.SYS_BPF, netlink, epoll). Run these on a Linux host / in CI:
//
//	go test -race -count=1 -run TestAttachDeleteResurrectionRace ./pkg/ebpf/
//
// The resurrection race below is a LOGICAL race (all shared Go state is a
// sync.Map, so `-race` will not flag it); detection is done by the post-condition
// assertion, and the loop drives the interleaving. `-race` is still recommended
// to catch any incidental memory races.

import (
	"sync"
	"testing"

	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

// TestAttachDeleteResurrectionRace validates Finding 3: AttacheBPFProbes reads the
// `deletedPods` guard BEFORE acquiring podIdentifierLock (bpf_client.go ~696-706),
// so a delete that interleaves between the check and the lock can be "undone" — the
// probe is re-attached and the prog<->pod caches are re-populated for a pod that was
// just deleted, leaving stale enforcement state that nothing cleans up.
//
// Sequence that reproduces it (hit whenever Delete wins the lock race, ~50%):
//  1. AttacheBPFProbes reads deletedPods[pod] -> absent, PASSES the guard (pre-lock).
//  2. DeleteBPFProbes takes the lock, removes the pod from the caches, and does
//     deletedPods.Store(pod), then releases the lock.
//  3. AttacheBPFProbes takes the lock, sees the pod "not attached" (caches were
//     cleared), re-attaches, and re-populates the caches.
//
// Post-condition that flags the bug: after both goroutines finish, the pod is present
// in deletedPods (delete happened) AND present in ingressPodToProgMap (attach
// resurrected it). In every correct interleaving only one of the two is true.
//
// EXPECTED: FAILS on current code (resurrections > 0). PASSES once AttacheBPFProbes
// re-checks deletedPods AFTER acquiring podIdentifierLock.
//
// The delete is driven down the SHARED-progFD path (isProgFdShared == true) so it does
// not tear down the program/maps — keeping the test free of any kernel/unpin syscalls.
func TestAttachDeleteResurrectionRace(t *testing.T) {
	const iterations = 500

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// TC attach is a no-op in this test (probe is reused, not loaded).
	mockTC := mock_tc.NewMockBpfTc(ctrl)
	mockTC.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockTC.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// Program is reused from the pre-seeded context, so LoadBpfFile is never expected
	// on the happy path; declare it AnyTimes defensively.
	mockSDK := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockSDK.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()

	// Stable host-veth name so attach does not depend on real pod netns naming.
	utils.GetHostVethName = func(_, _ string, _ int, _ []string) (string, error) {
		return "mockedveth0", nil
	}

	const (
		podName = "resurrect-pod"
		nsName  = "testns"
		sharer  = "sharer-pod"
		ingFD   = 3
		egrFD   = 5
	)
	pod := types.NamespacedName{Name: podName, Namespace: nsName}
	podID := utils.GetPodIdentifier(podName, nsName)
	podKey := utils.GetPodNamespacedName(podName, nsName)
	sharerKey := utils.GetPodNamespacedName(sharer, nsName)

	resurrections := 0

	for i := 0; i < iterations; i++ {
		client := &bpfClient{
			hostMask:                  "/32",
			bpfSDKClient:              mockSDK,
			bpfTCClient:               mockTC,
			policyEndpointeBPFContext: new(sync.Map),
			ingressPodToProgMap:       new(sync.Map),
			egressPodToProgMap:        new(sync.Map),
			ingressProgToPodsMap:      new(sync.Map),
			egressProgToPodsMap:       new(sync.Map),
			podIdentifierLock:         new(sync.Map),
			podNameToInterfaceCount:   new(sync.Map),
			deletedPods:               new(sync.Map),
			isMultiNICEnabled:         false,
		}

		// Pre-seed: pod is attached and its progFD is SHARED with `sharer`, so
		// DeleteBPFProbes takes the shared path (no program/map teardown).
		ctx := BPFContext{}
		ctx.ingressPgmInfo.Program.ProgFD = ingFD
		ctx.egressPgmInfo.Program.ProgFD = egrFD
		client.policyEndpointeBPFContext.Store(podID, ctx)

		client.ingressPodToProgMap.Store(podKey, ingFD)
		client.egressPodToProgMap.Store(podKey, egrFD)
		client.ingressPodToProgMap.Store(sharerKey, ingFD)
		client.egressPodToProgMap.Store(sharerKey, egrFD)
		client.ingressProgToPodsMap.Store(ingFD, map[string]struct{}{podKey: {}, sharerKey: {}})
		client.egressProgToPodsMap.Store(egrFD, map[string]struct{}{podKey: {}, sharerKey: {}})

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			_ = client.AttacheBPFProbes(pod, podID, INTERFACE_COUNT_UNKNOWN)
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = client.DeleteBPFProbes(pod, podID)
		}()

		close(start) // release both simultaneously
		wg.Wait()

		_, deleted := client.deletedPods.Load(podKey)
		_, stillAttached := client.ingressPodToProgMap.Load(podKey)
		if deleted && stillAttached {
			resurrections++
		}
	}

	assert.Equal(t, 0, resurrections,
		"AttacheBPFProbes resurrected a deleted pod in %d/%d iterations: the deletedPods "+
			"guard is checked before podIdentifierLock is held, so a concurrent delete is "+
			"undone. Re-check deletedPods after acquiring the lock.", resurrections, iterations)
}
