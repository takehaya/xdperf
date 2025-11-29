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
// Each entry is stored at a separate key (0, 1, 2, ..., N-1).
// All CPUs receive the same packet for each key.
func (x *Xdperf) initTxOverrideMap(entries []*TxOverrideEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("no entry")
	}

	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed get possible CPU: %w", err)
	}

	for i, e := range entries {
		ld := int(e.Length)
		if ld <= 0 {
			return fmt.Errorf("invalid entry length at index %d: %d", i, e.Length)
		}
		if ld > len(e.Data) {
			return fmt.Errorf("length %d exceeds data size %d at index %d", e.Length, len(e.Data), i)
		}

		// Create per-CPU array with the same packet for all CPUs
		entrylist := make([]coreelf.BpfPktTemplate, numCpus)
		for cpu := 0; cpu < numCpus; cpu++ {
			entrylist[cpu] = coreelf.BpfPktTemplate{
				Len: uint32(e.Length),
			}
			copy(entrylist[cpu].Data[:], e.Data)
		}

		key := uint32(i)
		if err := x.bpfobjs.BpfMaps.TxOverrideMap.Put(&key, entrylist); err != nil {
			return fmt.Errorf("failed put tx override map at key %d: %w", i, err)
		}
	}

	x.Logger.Info("tx override map populated",
		zap.Int("num_entries", len(entries)),
		zap.Int("num_cpus", numCpus),
	)

	return nil
}

func (x *Xdperf) initSeqStateMap() error {
	key := uint32(0)
	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed get possible CPU: %w", err)
	}
	entrylist := make([]uint32, numCpus)
	if err := x.bpfobjs.BpfMaps.SeqStateMap.Put(&key, entrylist); err != nil {
		return fmt.Errorf("failed put seq state map: %w", err)
	}
	return nil
}

func (x *Xdperf) initPktCountMap(countsPerCPU []uint32) error {
	key := uint32(0)
	if err := x.bpfobjs.BpfMaps.PktCountMap.Put(&key, countsPerCPU); err != nil {
		return fmt.Errorf("failed put pkt count map: %w", err)
	}
	return nil
}

func (x *Xdperf) initPktOffsetMap(offsetsPerCPU []uint32) error {
	key := uint32(0)
	if err := x.bpfobjs.BpfMaps.PktOffsetMap.Put(&key, offsetsPerCPU); err != nil {
		return fmt.Errorf("failed put pkt offset map: %w", err)
	}
	return nil
}

func (x *Xdperf) initEbpfMap(entries []*TxOverrideEntry) error {
	if err := x.initSeqStateMap(); err != nil {
		x.Logger.Error("failed to init seq state map", zap.Error(err))
		return fmt.Errorf("failed to init seq state map: %w", err)
	}
	x.Logger.Info("seq state map initialized")

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
	offsetsPerCPU := make([]uint32, numCpus)
	currentOffset := uint32(0)

	for cpu := 0; cpu < numCpus; cpu++ {
		if cpu < parallelism {
			count := entriesPerCPU
			if cpu < remainder {
				count++
			}
			countsPerCPU[cpu] = uint32(count)
			offsetsPerCPU[cpu] = currentOffset
			currentOffset += uint32(count)
		} else {
			// CPUs not in use get 0 count
			countsPerCPU[cpu] = 0
			offsetsPerCPU[cpu] = 0
		}
	}

	x.Logger.Info("packet distribution calculated",
		zap.Int("total_entries", totalEntries),
		zap.Int("parallelism", parallelism),
		zap.Int("num_cpus", numCpus),
		zap.Any("counts_per_cpu", countsPerCPU[:parallelism]),
		zap.Any("offsets_per_cpu", offsetsPerCPU[:parallelism]),
	)

	if err := x.initPktCountMap(countsPerCPU); err != nil {
		x.Logger.Error("failed to init pkt count map", zap.Error(err))
		return fmt.Errorf("failed to init pkt count map: %w", err)
	}
	x.Logger.Info("pkt count map initialized")

	if err := x.initPktOffsetMap(offsetsPerCPU); err != nil {
		x.Logger.Error("failed to init pkt offset map", zap.Error(err))
		return fmt.Errorf("failed to init pkt offset map: %w", err)
	}
	x.Logger.Info("pkt offset map initialized")

	if err := x.initTxOverrideMap(entries); err != nil {
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
