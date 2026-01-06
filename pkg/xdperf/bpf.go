package xdperf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// getBpfConstant reads a BPF constant value from spec.Variables
func (x *Xdperf) getBpfConstant(name string) int {
	if varSpec, ok := x.bpfSpec.Variables[name]; ok {
		var val uint32
		if err := varSpec.Get(&val); err == nil {
			return int(val)
		}
	}
	return 0
}

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
// Values are stored in network byte order (big-endian)
type DiffValue struct {
	OldValue [8]byte // Original value from base packet (network byte order)
	NewValue [8]byte // New value to write (network byte order)
	Offset   uint16
	Size     uint8
}

// initBasePacketMaps initializes the base packet map with multiple base packets
func (x *Xdperf) initBasePacketMaps(bases []BasePacketInfo, numCpus int) error {
	maxPacketSize := x.getBpfConstant("max_packet_size")
	minPacketSize := x.getBpfConstant("min_packet_size")
	for baseIdx, info := range bases {
		// Validate packet size bounds
		if int(info.Base.Length) < minPacketSize {
			return fmt.Errorf("base packet %d too small: %d bytes (minimum %d)",
				baseIdx, info.Base.Length, minPacketSize)
		}
		if int(info.Base.Length) > len(info.Base.Data) {
			return fmt.Errorf("base packet %d: length %d exceeds data size %d",
				baseIdx, info.Base.Length, len(info.Base.Data))
		}
		if int(info.Base.Length) > maxPacketSize {
			return fmt.Errorf("base packet %d: length %d exceeds max template size %d",
				baseIdx, info.Base.Length, maxPacketSize)
		}

		key := uint32(baseIdx)

		// Create base packet template once
		base := coreelf.BpfBasePacket{
			Len:           info.Base.Length,
			ChecksumCount: uint8(len(info.Checksums)),
		}
		copy(base.Data[:], info.Base.Data[:info.Base.Length])

		// Replicate to all CPUs (all CPUs get the same base packet)
		basePackets := make([]coreelf.BpfBasePacket, numCpus)
		for i := range basePackets {
			basePackets[i] = base
		}

		if err := x.bpfobjs.BpfMaps.BasePacketMap.Put(&key, basePackets); err != nil {
			return fmt.Errorf("failed to put base packet map at key %d: %w", baseIdx, err)
		}
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

	maxDiffsPerPacket := x.getBpfConstant("max_diffs_per_packet")

	// Check if any entry exceeds max diffs
	for i, e := range entries {
		if len(e.Diffs) > maxDiffsPerPacket {
			return fmt.Errorf("entry %d has %d diffs, exceeds MAX_DIFFS_PER_PACKET (%d)", i, len(e.Diffs), maxDiffsPerPacket)
		}
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

				// Copy diff values (up to maxDiffsPerPacket)
				for i, dv := range e.Diffs {
					if i >= maxDiffsPerPacket {
						break
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

// initChecksumMetaMaps initializes the checksum metadata map for all bases
// Key format: base_idx * MAX_CHECKSUM_ENTRIES + checksum_idx
func (x *Xdperf) initChecksumMetaMaps(bases []BasePacketInfo, numCpus int) error {
	maxChecksumEntriesPerBase := x.getBpfConstant("max_checksum_entries")

	totalChecksums := 0
	for baseIdx, info := range bases {
		// Warn if checksums exceed limit
		if len(info.Checksums) > maxChecksumEntriesPerBase {
			x.Logger.Warn("checksum count exceeds limit, truncating",
				zap.Int("base_idx", baseIdx),
				zap.Int("total_checksums", len(info.Checksums)),
				zap.Int("max_checksums", maxChecksumEntriesPerBase))
		}

		for csIdx, cs := range info.Checksums {
			if csIdx >= maxChecksumEntriesPerBase {
				break
			}

			key := uint32(baseIdx*maxChecksumEntriesPerBase + csIdx)
			meta := coreelf.BpfChecksumMeta{
				CsumOffset:     cs.ChecksumOffset,
				HeaderStart:    cs.HeaderStart,
				HeaderLen:      cs.HeaderLen,
				IpHeaderOffset: cs.IPHeaderOffset,
			}

			// Replicate to all CPUs (all CPUs get the same checksum metadata)
			metas := make([]coreelf.BpfChecksumMeta, numCpus)
			for i := range metas {
				metas[i] = meta
			}

			if err := x.bpfobjs.BpfMaps.ChecksumMetaMap.Put(&key, metas); err != nil {
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

	// Initialize BPF maps in order of dependency.
	// If initialization fails, this function returns an error and the BPF program
	// will not be executed. Maps are not pinned, so each run starts fresh.
	steps := []struct {
		name string
		fn   func() error
	}{
		{"base_packet_maps", func() error { return x.initBasePacketMaps(bases, numCpus) }},
		{"diff_map", func() error { return x.initDiffMap(diffEntries, countsPerCPU, numCpus) }},
		{"checksum_meta_maps", func() error { return x.initChecksumMetaMaps(bases, numCpus) }},
		{"pkt_state_map", func() error { return x.initPktStateMap(countsPerCPU) }},
	}

	var completed []string
	for _, step := range steps {
		if err := step.fn(); err != nil {
			if len(completed) > 0 {
				x.Logger.Warn("BPF map initialization failed after partial setup",
					zap.String("failed_at", step.name),
					zap.String("completed", strings.Join(completed, ", ")))
			}
			return fmt.Errorf("failed to init %s: %w", step.name, err)
		}
		completed = append(completed, step.name)
	}

	x.Logger.Info("BPF maps initialized")
	return nil
}
