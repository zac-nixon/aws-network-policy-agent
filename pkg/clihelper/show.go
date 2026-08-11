package clihelper

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfpgms "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	goebpfutils "github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

type PodState struct {
	State uint8
}

// formatLastSeen renders last_seen as an age. now must be a CLOCK_MONOTONIC
// reading, to match the clock the datapath stamps with.
func formatLastSeen(lastSeen, now uint64) string {
	if lastSeen == 0 {
		return "never"
	}
	if now == 0 || lastSeen > now {
		// Either the clock read failed, or the datapath stamped the entry after
		// we read the clock. Neither is an error, so avoid a negative age.
		return "0s ago"
	}
	return time.Duration(now-lastSeen).Round(time.Millisecond).String() + " ago"
}

// Show - Displays all loaded AWS BPF Programs and their associated maps
func Show() error {

	bpfSDKclient := goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps})
	bpfState, err := bpfSDKclient.GetAllBpfProgramsAndMaps()
	if err != nil {
		return err
	}

	for pinPath, bpfEntry := range bpfState {
		podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		fmt.Println("PinPath: ", pinPath)
		line := fmt.Sprintf("Pod Identifier : %s  Direction : %s \n", podIdentifier, direction)
		fmt.Print(line)
		bpfProg := bpfEntry.Program
		fmt.Println("Prog ID: ", bpfProg.ProgID)
		fmt.Println("Associated Maps -> ")
		bpfMaps := bpfEntry.Maps
		for k, v := range bpfMaps {
			fmt.Println("Map Name: ", k)
			fmt.Println("Map ID: ", v.MapID)
		}
		fmt.Println("========================================================================================")
	}
	return nil
}

// ProgShow - Lists out all programs created by AWS Network Policy Agent
func ProgShow() error {
	loadedPgms, err := goebpfpgms.BpfGetAllProgramInfo()
	if err != nil {
		return err
	}

	fmt.Println("Programs currently loaded : ")
	for _, loadedPgm := range loadedPgms {
		progInfo := fmt.Sprintf("Type : %d ID : %d Associated maps count : %d", loadedPgm.Type, loadedPgm.ID, loadedPgm.NrMapIDs)
		fmt.Println(progInfo)
		fmt.Println("========================================================================================")
	}
	return nil
}

// MapShow - Lists out all active maps created by AWS Network Policy Agent
func MapShow() error {
	loadedMaps, err := goebpfmaps.BpfGetAllMapInfo()
	if err != nil {
		return err
	}

	fmt.Println("Maps currently loaded : ")
	for _, loadedMap := range loadedMaps {
		mapInfo := fmt.Sprintf("Type : %d ID : %d", loadedMap.Type, loadedMap.Id)
		fmt.Println(mapInfo)
		mapInfo = fmt.Sprintf("Keysize %d Valuesize %d MaxEntries %d", loadedMap.KeySize, loadedMap.ValueSize, loadedMap.MaxEntries)
		fmt.Println(mapInfo)
		fmt.Println("========================================================================================")
	}
	return nil
}

// dumpClusterPolicyEntry prints a single Cluster NP entry from the map
func dumpClusterPolicyEntry(key utils.BPFTrieKey, mapID int) error {
	var values [24]utils.BPFL4PriorityVal
	if err := goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&values)), mapID); err != nil {
		return fmt.Errorf("unable to get map entry: %w", err)
	}
	fmt.Printf("Key: %s/%d\n", utils.ConvIntToIPv4(key.IP), key.PrefixLen)
	printPolicyEntry(key, values)
	return nil
}

// dumpNetworkPolicyEntry prints a single NP entry from the map
func dumpNetworkPolicyEntry(key utils.BPFTrieKey, mapID int) error {
	var values [24]utils.BPFTrieVal
	if err := goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&values)), mapID); err != nil {
		return fmt.Errorf("unable to get map entry: %w", err)
	}
	printPolicyEntry(key, values)
	return nil
}

// printPolicyEntry handles shared printing logic for any []BPFTrieVal-like type
func printPolicyEntry[T any](key utils.BPFTrieKey, entries [24]T) {

	fmt.Printf("Key: %s/%d\n", utils.ConvIntToIPv4(key.IP), key.PrefixLen)
	for i := 0; i < len(entries); i++ {
		entry := any(entries[i])
		switch v := entry.(type) {
		case utils.BPFTrieVal:
			if v.Protocol == 0 {
				continue
			}
			fmt.Println("-------------------")
			fmt.Printf("Entry %d:\n", i)
			fmt.Println("Protocol  -", utils.GetProtocol(int(v.Protocol)))
			fmt.Println("StartPort -", v.StartPort)
			fmt.Println("EndPort   -", v.EndPort)
			fmt.Println("-------------------")

		case utils.BPFL4PriorityVal:
			if v.Protocol == 0 {
				continue
			}
			fmt.Println("-------------------")
			fmt.Printf("Entry %d:\n", i)
			fmt.Println("Protocol  -", utils.GetProtocol(int(v.Protocol)))
			fmt.Println("Priority  -", v.Priority)
			fmt.Println("StartPort -", v.StartPort)
			fmt.Println("EndPort   -", v.EndPort)
			fmt.Println("-------------------")
		}
	}
	fmt.Println("*******************************")
}

// MapWalkAuto dumps the contents of a single map, auto-detecting the IP family
// from the kernel-reported key size. The operator no longer needs to know
// whether the node is running in IPv4 or IPv6 mode: LPM_TRIE and LRU_HASH maps
// carry family-specific key layouts (an IPv4 address is 4 bytes, an IPv6
// address is 16), so their key size is an unambiguous discriminator. HASH maps
// (pod_state_map) hold no address and are decoded the same way for both
// families.
func MapWalkAuto(mapID int) error {
	if mapID <= 0 {
		return fmt.Errorf("Invalid mapID")
	}

	mapFD, err := goebpfutils.GetMapFDFromID(mapID)
	if err != nil {
		return fmt.Errorf("failed to get map FD: %w", err)
	}

	mapInfo, err := goebpfmaps.GetBPFmapInfo(mapFD)
	unix.Close(mapFD)
	if err != nil {
		return fmt.Errorf("failed to get map info: %w", err)
	}

	switch mapInfo.Type {
	case constdef.BPF_MAP_TYPE_LPM_TRIE.Index():
		switch mapInfo.KeySize {
		case uint32(unsafe.Sizeof(utils.BPFTrieKey{})): // IPv4 (8 bytes)
			return walkPolicyTrieV4(mapID, false)
		case uint32(unsafe.Sizeof(utils.BPFTrieKeyV6{})): // IPv6 (20 bytes)
			return walkPolicyTrieV6(mapID)
		default:
			return fmt.Errorf("unexpected LPM_TRIE key size %d (want %d for IPv4 or %d for IPv6)",
				mapInfo.KeySize, unsafe.Sizeof(utils.BPFTrieKey{}), unsafe.Sizeof(utils.BPFTrieKeyV6{}))
		}
	case constdef.BPF_MAP_TYPE_LRU_HASH.Index():
		switch mapInfo.KeySize {
		case uint32(unsafe.Sizeof(utils.ConntrackKey{})): // IPv4 (24 bytes)
			return walkConntrackV4(mapID)
		case uint32(unsafe.Sizeof(utils.ConntrackKeyV6{})): // IPv6 (60 bytes)
			return walkConntrackV6(mapID)
		default:
			return fmt.Errorf("unexpected LRU_HASH key size %d (want %d for IPv4 or %d for IPv6)",
				mapInfo.KeySize, unsafe.Sizeof(utils.ConntrackKey{}), unsafe.Sizeof(utils.ConntrackKeyV6{}))
		}
	case constdef.BPF_MAP_TYPE_HASH.Index():
		return walkPodState(mapID)
	default:
		return fmt.Errorf("unsupported map type: %d (expected LPM_TRIE, LRU_HASH, or HASH)", mapInfo.Type)
	}
}

// MapWalkCP dumps a Cluster Network Policy LPM_TRIE map (IPv4). Cluster vs.
// pod-scoped policy is not distinguishable from the key size, so this remains an
// explicit entry point rather than part of MapWalkAuto's detection.
func MapWalkCP(mapID int) error {
	if mapID <= 0 {
		return fmt.Errorf("Invalid mapID")
	}
	return walkPolicyTrieV4(mapID, true)
}

// walkPolicyTrieV4 walks an IPv4 policy LPM_TRIE. When clusterPolicy is true the
// entries are decoded as Cluster Network Policy values, otherwise as pod-scoped
// Network Policy values.
func walkPolicyTrieV4(mapID int, clusterPolicy bool) error {
	var iterKey, iterNextKey utils.BPFTrieKey

	err := goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("No Entries found, Empty map")
			return nil
		}
		return fmt.Errorf("Unable to get First key: %v", err)
	}

	for {
		if clusterPolicy {
			if err := dumpClusterPolicyEntry(iterKey, mapID); err != nil {
				fmt.Printf("error reading ClusterNetworkPolicy entry: %v\n", err)
			}
		} else {
			if err := dumpNetworkPolicyEntry(iterKey, mapID); err != nil {
				fmt.Printf("error reading NetworkPolicy entry: %v\n", err)
			}
		}

		err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)), mapID)
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("Done reading all entries")
			break
		}
		if err != nil {
			fmt.Println("Failed to get next entry Done searching")
			break
		}
		iterKey = iterNextKey
	}

	return nil
}

// walkConntrackV4 walks an IPv4 conntrack LRU_HASH map.
func walkConntrackV4(mapID int) error {
	iterKey := utils.ConntrackKey{}
	iterNextKey := utils.ConntrackKey{}
	// Read once so every entry in this dump is aged against the same instant.
	// A failure here only costs the age column, so carry on with the dump.
	dumpNow, clockErr := utils.KtimeGetNs()
	if clockErr != nil {
		fmt.Printf("unable to read monotonic clock, ages will show as 0s: %v\n", clockErr)
	}
	err := goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), mapID)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("No Entries found, Empty map")
			return nil
		}
		return fmt.Errorf("Unable to get First key: %v", err)
	}
	for {
		iterValue := utils.ConntrackVal{}
		err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterValue)), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get map entry: %v", err)
		}
		retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d", utils.ConvIntToIPv4(iterKey.Source_ip).String(), iterKey.Source_port, utils.ConvIntToIPv4(iterKey.Dest_ip).String(), iterKey.Dest_port, iterKey.Protocol, utils.ConvIntToIPv4(iterKey.Owner_ip).String(), iterKey.Ifindex)
		fmt.Println(retrievedKey)
		fmt.Println("Value : ")
		fmt.Println("Conntrack Val - ", iterValue.Value)
		fmt.Printf("Last Seen (ns) -  %d  (%s)\n", iterValue.LastSeen, formatLastSeen(iterValue.LastSeen, dumpNow))
		fmt.Println("*******************************")

		err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)), mapID)
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("Done reading all entries")
			break
		}
		if err != nil {
			fmt.Println("Failed to get next entry Done searching")
			break
		}
		iterKey = iterNextKey
	}

	return nil
}

// walkPodState walks a pod_state_map HASH map. The layout is identical for IPv4
// and IPv6, so a single decoder serves both families.
func walkPodState(mapID int) error {
	var key, nextKey uint32
	// Get the first entry
	err := goebpfmaps.GetFirstMapEntryByID(
		uintptr(unsafe.Pointer(&key)),
		mapID)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("No entries found, empty HASH map (pod_state_map?)")
			return nil
		}
		return fmt.Errorf("unable to get first key (HASH): %v", err)
	}

	for {
		var val PodState
		err = goebpfmaps.GetMapEntryByID(
			uintptr(unsafe.Pointer(&key)),
			uintptr(unsafe.Pointer(&val)),
			mapID)
		if err != nil {
			return fmt.Errorf("unable to get HASH entry for key=%d: %v", key, err)
		}

		fmt.Println("Key : ", key)
		fmt.Println("State - ", val.State)
		fmt.Println("*******************************")

		err = goebpfmaps.GetNextMapEntryByID(
			uintptr(unsafe.Pointer(&key)),
			uintptr(unsafe.Pointer(&nextKey)),
			mapID)
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("Done reading all entries in BPF_MAP_TYPE_HASH")
			break
		}
		if err != nil {
			fmt.Println("Failed to get next entry, done searching")
			break
		}
		key = nextKey
	}

	return nil
}

// walkPolicyTrieV6 walks an IPv6 policy LPM_TRIE map.
func walkPolicyTrieV6(mapID int) error {
	iterKey := utils.BPFTrieKeyV6{}
	iterNextKey := utils.BPFTrieKeyV6{}

	byteSlice := utils.ConvTrieV6ToByte(iterKey)
	nextbyteSlice := utils.ConvTrieV6ToByte(iterNextKey)

	err := goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
	if err != nil {
		return fmt.Errorf("Unable to get First key: %v", err)
	}
	for {
		iterValue := [24]utils.BPFTrieVal{}

		err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get map entry: %v", err)
		}
		v6key := utils.ConvByteToTrieV6(byteSlice)
		retrievedKey := fmt.Sprintf("Key : IP/Prefixlen - %s/%d ", utils.ConvByteToIPv6(v6key.IP).String(), v6key.PrefixLen)
		fmt.Println(retrievedKey)
		for i := 0; i < len(iterValue); i++ {
			if iterValue[i].Protocol == 0 {
				continue
			}
			fmt.Println("-------------------")
			fmt.Println("Value Entry : ", i)
			fmt.Println("Protocol - ", utils.GetProtocol(int(iterValue[i].Protocol)))
			fmt.Println("StartPort - ", iterValue[i].StartPort)
			fmt.Println("Endport - ", iterValue[i].EndPort)
			fmt.Println("-------------------")
		}
		fmt.Println("*******************************")

		err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&nextbyteSlice[0])), mapID)
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("Done reading all entries")
			break
		}
		if err != nil {
			fmt.Println("Failed to get next entry Done searching")
			break
		}
		copy(byteSlice, nextbyteSlice)
	}

	return nil
}

// walkConntrackV6 walks an IPv6 conntrack LRU_HASH map.
func walkConntrackV6(mapID int) error {
	iterKey := utils.ConntrackKeyV6{}
	iterNextKey := utils.ConntrackKeyV6{}

	byteSlice := utils.ConvConntrackV6ToByte(iterKey)
	nextbyteSlice := utils.ConvConntrackV6ToByte(iterNextKey)

	// Read once so every entry in this dump is aged against the same instant.
	// A failure here only costs the age column, so carry on with the dump.
	dumpNow, clockErr := utils.KtimeGetNs()
	if clockErr != nil {
		fmt.Printf("unable to read monotonic clock, ages will show as 0s: %v\n", clockErr)
	}
	err := goebpfmaps.GetFirstMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), mapID)
	if err != nil {
		return fmt.Errorf("Unable to get First key: %v", err)
	}
	for {
		iterValue := utils.ConntrackVal{}
		err = goebpfmaps.GetMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&iterValue)), mapID)
		if err != nil {
			return fmt.Errorf("Unable to get map entry: %v", err)
		}
		v6key := utils.ConvByteToConntrackV6(byteSlice)
		retrievedKey := fmt.Sprintf("Conntrack Key : Source IP - %s Source port - %d Dest IP - %s Dest port - %d Protocol - %d Owner IP - %s Ifindex - %d", utils.ConvByteToIPv6(v6key.Source_ip).String(), v6key.Source_port, utils.ConvByteToIPv6(v6key.Dest_ip).String(), v6key.Dest_port, v6key.Protocol, utils.ConvByteToIPv6(v6key.Owner_ip).String(), v6key.Ifindex)
		fmt.Println(retrievedKey)
		fmt.Println("Value : ")
		fmt.Println("Conntrack Val - ", iterValue.Value)
		fmt.Printf("Last Seen (ns) -  %d  (%s)\n", iterValue.LastSeen, formatLastSeen(iterValue.LastSeen, dumpNow))
		fmt.Println("*******************************")

		err = goebpfmaps.GetNextMapEntryByID(uintptr(unsafe.Pointer(&byteSlice[0])), uintptr(unsafe.Pointer(&nextbyteSlice[0])), mapID)
		if errors.Is(err, unix.ENOENT) {
			fmt.Println("Done reading all entries")
			break
		}
		if err != nil {
			fmt.Println("Failed to get next entry Done searching")
			break
		}
		copy(byteSlice, nextbyteSlice)
	}

	return nil
}
