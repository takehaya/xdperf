package xdperf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// DiffEntry represents a single diff entry for differential packet generation
type DiffEntry struct {
	PacketLen uint16
	Diffs     []DiffValue
}

// DiffValue represents a single diff value
type DiffValue struct {
	Offset uint16
	Size   uint8
	Value  uint32
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

// initBasePacketMap initializes the base packet map with a single base packet
func (x *Xdperf) initBasePacketMap(base guest.BasePacket, diffCount uint8, checksumCount uint8, numCpus int) error {
	key := uint32(0)

	// Create per-CPU values (all CPUs get the same base packet)
	basePackets := make([]coreelf.BpfBasePacket, numCpus)
	for i := 0; i < numCpus; i++ {
		basePackets[i] = coreelf.BpfBasePacket{
			Len:           base.Length,
			DiffCount:     diffCount,
			ChecksumCount: checksumCount,
		}
		copy(basePackets[i].Data[:], base.Data)
	}

	if err := x.bpfobjs.BpfMaps.BasePacketMap.Put(&key, basePackets); err != nil {
		return fmt.Errorf("failed to put base packet map: %w", err)
	}

	x.Logger.Info("base packet map initialized",
		zap.Uint16("base_len", base.Length),
		zap.Uint8("diff_count", diffCount),
		zap.Uint8("checksum_count", checksumCount),
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
				entrylist[cpu] = coreelf.BpfDiffEntry{
					PktLen:    e.PacketLen,
					DiffCount: uint8(len(e.Diffs)),
				}

				// Copy diff values
				for i, dv := range e.Diffs {
					if i >= 8 {
						break // MAX_DIFFS_PER_PACKET
					}
					entrylist[cpu].Diffs[i].Offset = dv.Offset
					entrylist[cpu].Diffs[i].Size = dv.Size
					entrylist[cpu].Diffs[i].Value = dv.Value
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

// initChecksumMetaMap initializes the checksum metadata map
func (x *Xdperf) initChecksumMetaMap(checksums []guest.ChecksumSpec) error {
	for i, cs := range checksums {
		if i >= 8 {
			break // MAX_CHECKSUM_ENTRIES
		}

		key := uint32(i)
		meta := coreelf.BpfChecksumMeta{
			CsumType:       checksumTypeToBPF(cs.Type),
			CsumOffset:     cs.ChecksumOffset,
			HeaderStart:    cs.HeaderStart,
			HeaderLen:      cs.HeaderLen,
			IpHeaderOffset: cs.IPHeaderOffset,
		}

		if err := x.bpfobjs.BpfMaps.ChecksumMetaMap.Put(&key, &meta); err != nil {
			return fmt.Errorf("failed to put checksum meta map at key %d: %w", i, err)
		}
	}

	x.Logger.Info("checksum meta map initialized",
		zap.Int("num_checksums", len(checksums)),
	)

	return nil
}

// initDiffPktStateMap initializes the differential packet state map
func (x *Xdperf) initDiffPktStateMap(countsPerCPU []uint32) error {
	key := uint32(0)
	states := make([]coreelf.BpfDiffPktState, len(countsPerCPU))
	for i, count := range countsPerCPU {
		states[i] = coreelf.BpfDiffPktState{Count: count, Idx: 0}
	}
	if err := x.bpfobjs.BpfMaps.DiffPktStateMap.Put(&key, states); err != nil {
		return fmt.Errorf("failed to put diff pkt state map: %w", err)
	}
	return nil
}

// initDifferentialMaps initializes all maps needed for differential packet generation
func (x *Xdperf) initDifferentialMaps(base guest.BasePacket, diffEntries []DiffEntry, checksums []guest.ChecksumSpec) error {
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

	x.Logger.Info("differential packet distribution calculated",
		zap.Int("total_entries", totalEntries),
		zap.Int("parallelism", parallelism),
		zap.Int("num_cpus", numCpus),
		zap.Any("counts_per_cpu", countsPerCPU[:parallelism]),
	)

	// Initialize base packet map
	diffCount := uint8(0)
	if len(diffEntries) > 0 && len(diffEntries[0].Diffs) > 0 {
		diffCount = uint8(len(diffEntries[0].Diffs))
	}
	if err := x.initBasePacketMap(base, diffCount, uint8(len(checksums)), numCpus); err != nil {
		return fmt.Errorf("failed to init base packet map: %w", err)
	}

	// Initialize diff map
	if err := x.initDiffMap(diffEntries, countsPerCPU, numCpus); err != nil {
		return fmt.Errorf("failed to init diff map: %w", err)
	}

	// Initialize checksum meta map
	if err := x.initChecksumMetaMap(checksums); err != nil {
		return fmt.Errorf("failed to init checksum meta map: %w", err)
	}

	// Initialize diff packet state map
	if err := x.initDiffPktStateMap(countsPerCPU); err != nil {
		return fmt.Errorf("failed to init diff pkt state map: %w", err)
	}

	x.Logger.Info("all differential maps initialized successfully")
	return nil
}
