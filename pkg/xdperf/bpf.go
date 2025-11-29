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

func (x *Xdperf) initPktCountMap(count uint32) error {
	key := uint32(0)
	if err := x.bpfobjs.BpfMaps.PktCountMap.Put(&key, &count); err != nil {
		return fmt.Errorf("failed put pkt count map: %w", err)
	}
	return nil
}

func (x *Xdperf) initEbpfMap(entries []*TxOverrideEntry) error {
	if err := x.initSeqStateMap(); err != nil {
		x.Logger.Error("failed to init seq state map", zap.Error(err))
		return fmt.Errorf("failed to init seq state map: %w", err)
	}
	x.Logger.Info("seq state map initialized")

	if err := x.initPktCountMap(uint32(len(entries))); err != nil {
		x.Logger.Error("failed to init pkt count map", zap.Error(err))
		return fmt.Errorf("failed to init pkt count map: %w", err)
	}
	x.Logger.Info("pkt count map initialized", zap.Int("count", len(entries)))

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
