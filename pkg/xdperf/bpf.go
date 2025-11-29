package xdperf

import (
	"fmt"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

type TxOverrideEntry struct {
	Data   []byte
	Length uint16
}

// initTxOverrideMap initializes the TX Override Map with packet entries.
// Each CPU receives only its assigned packets at indices 0..count-1.
// This is memory efficient: only totalCount packets are stored, not totalCount * numCPUs.
func (x *Xdperf) initTxOverrideMap(entries []*TxOverrideEntry, countsPerCPU []uint32, numCpus int) error {
	if len(entries) == 0 {
		return fmt.Errorf("no entry")
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

	// For each local index (0..maxCount-1), store the appropriate packet for each CPU
	for localIdx := uint32(0); localIdx < maxCount; localIdx++ {
		entrylist := make([]coreelf.BpfPktTemplate, numCpus)

		for cpu := 0; cpu < numCpus; cpu++ {
			if localIdx < countsPerCPU[cpu] {
				globalIdx := cpuOffsets[cpu] + localIdx
				if int(globalIdx) >= len(entries) {
					return fmt.Errorf("globalIdx %d out of range for entries (len=%d)", globalIdx, len(entries))
				}

				e := entries[globalIdx]
				ld := int(e.Length)
				if ld <= 0 {
					return fmt.Errorf("invalid entry length at globalIdx %d: %d", globalIdx, e.Length)
				}
				if ld > len(e.Data) {
					return fmt.Errorf("length %d exceeds data size %d at globalIdx %d", e.Length, len(e.Data), globalIdx)
				}

				entrylist[cpu] = coreelf.BpfPktTemplate{
					Len: uint32(e.Length),
				}
				copy(entrylist[cpu].Data[:], e.Data)
			}
			// else: CPU not using this index, leave as zero value
		}

		key := localIdx
		if err := x.bpfobjs.BpfMaps.TxOverrideMap.Put(&key, entrylist); err != nil {
			return fmt.Errorf("failed put tx override map at key %d: %w", localIdx, err)
		}
	}

	x.Logger.Info("tx override map populated",
		zap.Int("num_entries", len(entries)),
		zap.Int("num_cpus", numCpus),
		zap.Uint32("max_count_per_cpu", maxCount),
	)

	return nil
}

func (x *Xdperf) initPktStateMap(countsPerCPU []uint32) error {
	key := uint32(0)
	states := make([]coreelf.BpfPktState, len(countsPerCPU))
	for i, count := range countsPerCPU {
		states[i] = coreelf.BpfPktState{Count: count, Idx: 0}
	}
	if err := x.bpfobjs.BpfMaps.PktStateMap.Put(&key, states); err != nil {
		return fmt.Errorf("failed put pkt state map: %w", err)
	}
	return nil
}


func (x *Xdperf) initEbpfMap(entries []*TxOverrideEntry) error {
	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed get possible CPU: %w", err)
	}

	parallelism := x.cfg.Parallelism
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > numCpus {
		parallelism = numCpus
	}

	// Distribute packets across CPUs that will be used
	totalEntries := len(entries)
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
			// CPUs not in use get 0 count
			countsPerCPU[cpu] = 0
		}
	}

	x.Logger.Info("packet distribution calculated",
		zap.Int("total_entries", totalEntries),
		zap.Int("parallelism", parallelism),
		zap.Int("num_cpus", numCpus),
		zap.Any("counts_per_cpu", countsPerCPU[:parallelism]),
	)

	if err := x.initPktStateMap(countsPerCPU); err != nil {
		x.Logger.Error("failed to init pkt state map", zap.Error(err))
		return fmt.Errorf("failed to init pkt state map: %w", err)
	}
	x.Logger.Info("pkt state map initialized")

	if err := x.initTxOverrideMap(entries, countsPerCPU, numCpus); err != nil {
		x.Logger.Error("failed to init tx override map", zap.Error(err))
		return fmt.Errorf("failed to init tx override map: %w", err)
	}
	x.Logger.Info("tx override map initialized")
	return nil
}

type XdpMd struct {
	_              structs.HostLayout
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}
