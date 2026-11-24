package ebpf

import (
	"sync"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
)

// Tests run without a kernel, so pod_state seeds land here, keyed by map ID then map key,
// instead of in a BPF map.
var (
	seededPodStatesMu sync.Mutex
	seededPodStates   = map[uint32]map[uint32]uint8{}
)

func init() {
	createPodStateEntry = func(podStateMap *goebpfmaps.BpfMap, key uint32, value pod_state) error {
		seededPodStatesMu.Lock()
		defer seededPodStatesMu.Unlock()
		if seededPodStates[podStateMap.MapID] == nil {
			seededPodStates[podStateMap.MapID] = map[uint32]uint8{}
		}
		if _, exists := seededPodStates[podStateMap.MapID][key]; !exists {
			seededPodStates[podStateMap.MapID][key] = value.state
		}
		return nil
	}
}

// seededPodState returns the seed recorded for key in the map with mapID.
func seededPodState(mapID uint32, key uint32) (uint8, bool) {
	seededPodStatesMu.Lock()
	defer seededPodStatesMu.Unlock()
	state, ok := seededPodStates[mapID][key]
	return state, ok
}
