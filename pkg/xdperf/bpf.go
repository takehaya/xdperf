package xdperf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// DiffEntry represents a single packet entry with optional modifications
type DiffEntry struct {
	BaseIdx    uint8  // Index into base_packet_map (which base to use)
	PacketLen  uint16
	LenChanged bool // True if packet length differs from base (requires full checksum recalculation)
	Diffs      []DiffValue
}

// BasePacketInfo contains base packet and its checksums
type BasePacketInfo struct {
	Base      guest.BasePacket
	Checksums []guest.ChecksumSpec
}

// DiffValue represents a single diff value
type DiffValue struct {
	Offset   uint16
	Size     uint8
	OldValue uint32 // Original value from base packet
	NewValue uint32 // New value to write
}

// checksumTypeToBPF converts guest.ChecksumType to BPF constant
func checksumTypeToBPF(t guest.ChecksumType) uint8 {
	switch t {
	case guest.ChecksumTypeIPv4Header:
		return 0 // CSUM_TYPE_IPV4_HEADER
	case guest.ChecksumTypeUDPIPv4:
		return 1 // CSUM_TYPE_UDP_IPV4
	case guest.ChecksumTypeTCPIPv4:
		return 2 // CSUM_TYPE_TCP_IPV4
	case guest.ChecksumTypeUDPIPv6:
		return 3 // CSUM_TYPE_UDP_IPV6
	case guest.ChecksumTypeTCPIPv6:
		return 4 // CSUM_TYPE_TCP_IPV6
	case guest.ChecksumTypeICMPv6:
		return 5 // CSUM_TYPE_ICMPV6
	default:
		return 0
	}
}

// initBasePacketMaps initializes the base packet map with multiple base packets
func (x *Xdperf) initBasePacketMaps(bases []BasePacketInfo, numCpus int) error {
	for baseIdx, info := range bases {
		key := uint32(baseIdx)

		// Create per-CPU values (all CPUs get the same base packet)
		basePackets := make([]coreelf.BpfBasePacket, numCpus)
		for i := 0; i < numCpus; i++ {
			basePackets[i] = coreelf.BpfBasePacket{
				Len:           info.Base.Length,
				DiffCount:     0, // Not used in current implementation
				ChecksumCount: uint8(len(info.Checksums)),
			}
			copy(basePackets[i].Data[:], info.Base.Data)
		}

		if err := x.bpfobjs.BpfMaps.BasePacketMap.Put(&key, basePackets); err != nil {
			return fmt.Errorf("failed to put base packet map at key %d: %w", baseIdx, err)
		}

		x.Logger.Debug("base packet initialized",
			zap.Int("base_idx", baseIdx),
			zap.Uint16("base_len", info.Base.Length),
			zap.Int("checksum_count", len(info.Checksums)),
		)
	}

	x.Logger.Info("base packet maps initialized",
		zap.Int("num_bases", len(bases)),
	)

	return nil
}

// initDiffMap initializes the diff map with pre-computed diff entries
func (x *Xdperf) initDiffMap(entries []DiffEntry, countsPerCPU []uint32, numCpus int) error {
	if len(entries) == 0 {
		return fmt.Errorf("no diff entries")
	}

	// Calculate starting offset for each CPU in the entries slice
	cpuOffsets := make([]uint32, numCpus)
	for cpu := 1; cpu < numCpus; cpu++ {
		cpuOffsets[cpu] = cpuOffsets[cpu-1] + countsPerCPU[cpu-1]
	}

	// Find maximum count across all CPUs
	var maxCount uint32
	for _, c := range countsPerCPU {
		if c > maxCount {
			maxCount = c
		}
	}

	// For each local index, store the appropriate diff entry for each CPU
	for localIdx := uint32(0); localIdx < maxCount; localIdx++ {
		entrylist := make([]coreelf.BpfDiffEntry, numCpus)

		for cpu := 0; cpu < numCpus; cpu++ {
			if localIdx < countsPerCPU[cpu] {
				globalIdx := cpuOffsets[cpu] + localIdx
				if int(globalIdx) >= len(entries) {
					return fmt.Errorf("globalIdx %d out of range for entries (len=%d)", globalIdx, len(entries))
				}

				e := entries[globalIdx]
				var lenChanged uint8
				if e.LenChanged {
					lenChanged = 1
				}
				entrylist[cpu] = coreelf.BpfDiffEntry{
					BaseIdx:    e.BaseIdx,
					DiffCount:  uint8(len(e.Diffs)),
					PktLen:     e.PacketLen,
					LenChanged: lenChanged,
				}

				// Copy diff values
				for i, dv := range e.Diffs {
					if i >= 8 {
						break // MAX_DIFFS_PER_PACKET
					}
					entrylist[cpu].Diffs[i].Offset = dv.Offset
					entrylist[cpu].Diffs[i].Size = dv.Size
					entrylist[cpu].Diffs[i].OldValue = dv.OldValue
					entrylist[cpu].Diffs[i].NewValue = dv.NewValue
				}
			}
			// else: CPU not using this index, leave as zero value
		}

		key := localIdx
		if err := x.bpfobjs.BpfMaps.DiffMap.Put(&key, entrylist); err != nil {
			return fmt.Errorf("failed to put diff map at key %d: %w", localIdx, err)
		}
	}

	x.Logger.Info("diff map populated",
		zap.Int("num_entries", len(entries)),
		zap.Int("num_cpus", numCpus),
		zap.Uint32("max_count_per_cpu", maxCount),
	)

	return nil
}

// MAX_CHECKSUM_ENTRIES must match the BPF definition
const maxChecksumEntriesPerBase = 4

// initChecksumMetaMaps initializes the checksum metadata map for all bases
// Key format: base_idx * MAX_CHECKSUM_ENTRIES + checksum_idx
func (x *Xdperf) initChecksumMetaMaps(bases []BasePacketInfo) error {
	totalChecksums := 0
	for baseIdx, info := range bases {
		for csIdx, cs := range info.Checksums {
			if csIdx >= maxChecksumEntriesPerBase {
				break // MAX_CHECKSUM_ENTRIES per base
			}

			key := uint32(baseIdx*maxChecksumEntriesPerBase + csIdx)
			meta := coreelf.BpfChecksumMeta{
				CsumType:       checksumTypeToBPF(cs.Type),
				CsumOffset:     cs.ChecksumOffset,
				HeaderStart:    cs.HeaderStart,
				HeaderLen:      cs.HeaderLen,
				IpHeaderOffset: cs.IPHeaderOffset,
			}

			if err := x.bpfobjs.BpfMaps.ChecksumMetaMap.Put(&key, &meta); err != nil {
				return fmt.Errorf("failed to put checksum meta map at key %d (base=%d, cs=%d): %w", key, baseIdx, csIdx, err)
			}
			totalChecksums++
		}
	}

	x.Logger.Info("checksum meta maps initialized",
		zap.Int("num_bases", len(bases)),
		zap.Int("total_checksums", totalChecksums),
	)

	return nil
}

// initPktStateMap initializes the packet state map
func (x *Xdperf) initPktStateMap(countsPerCPU []uint32) error {
	key := uint32(0)
	states := make([]coreelf.BpfPktState, len(countsPerCPU))
	for i, count := range countsPerCPU {
		states[i] = coreelf.BpfPktState{Count: count, Idx: 0}
	}
	if err := x.bpfobjs.BpfMaps.PktStateMap.Put(&key, states); err != nil {
		return fmt.Errorf("failed to put pkt state map: %w", err)
	}
	return nil
}

// initBpfMaps initializes all BPF maps for packet generation
func (x *Xdperf) initBpfMaps(bases []BasePacketInfo, diffEntries []DiffEntry) error {
	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible CPU: %w", err)
	}

	parallelism := x.cfg.Parallelism
	if parallelism <= 0 {
		x.Logger.Warn("invalid parallelism config, defaulting to 1", zap.Int("configured_parallelism", parallelism))
		parallelism = 1
	}
	if parallelism > numCpus {
		parallelism = numCpus
	}

	// Distribute diff entries across CPUs
	totalEntries := len(diffEntries)
	entriesPerCPU := totalEntries / parallelism
	remainder := totalEntries % parallelism

	countsPerCPU := make([]uint32, numCpus)
	for cpu := 0; cpu < numCpus; cpu++ {
		if cpu < parallelism {
			count := entriesPerCPU
			if cpu < remainder {
				count++
			}
			countsPerCPU[cpu] = uint32(count)
		} else {
			countsPerCPU[cpu] = 0
		}
	}

	x.Logger.Info("packet distribution calculated",
		zap.Int("total_entries", totalEntries),
		zap.Int("num_bases", len(bases)),
		zap.Int("parallelism", parallelism),
		zap.Int("num_cpus", numCpus),
		zap.Any("counts_per_cpu", countsPerCPU[:parallelism]),
	)

	// Initialize base packet maps (multiple bases)
	if err := x.initBasePacketMaps(bases, numCpus); err != nil {
		return fmt.Errorf("failed to init base packet maps: %w", err)
	}

	// Initialize diff map
	if err := x.initDiffMap(diffEntries, countsPerCPU, numCpus); err != nil {
		return fmt.Errorf("failed to init diff map: %w", err)
	}

	// Initialize checksum meta maps (per base)
	if err := x.initChecksumMetaMaps(bases); err != nil {
		return fmt.Errorf("failed to init checksum meta maps: %w", err)
	}

	// Initialize packet state map
	if err := x.initPktStateMap(countsPerCPU); err != nil {
		return fmt.Errorf("failed to init pkt state map: %w", err)
	}

	x.Logger.Info("BPF maps initialized")
	return nil
}
