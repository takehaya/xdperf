package xdperf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

type TxOverrideEntry struct {
	Data   []byte
	Length uint16
}

// percpu ごとに TX Override Map を初期化
// 分散してパケットを入れるようにする
func (x *Xdperf) initTxOverrideMap(entry []*TxOverrideEntry) error {
	if len(entry) == 0 {
		return fmt.Errorf("no entry")
	}
	key := uint32(0)
	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed get possible CPU: %w", err)
	}
	entrycount := len(entry)
	entrylist := make([]coreelf.BpfPktTemplate, numCpus)
	for cpu := 0; cpu < numCpus; cpu++ {
		idx := cpu % entrycount
		e := *entry[idx]
		if e.Length <= 0 || int(e.Length) >= len(e.Data) {
			return fmt.Errorf("invalid entry length: %d", e.Length)
		}

		entrylist[cpu] = coreelf.BpfPktTemplate{
			Len: uint32(e.Length),
		}
		copy(entrylist[cpu].Data[:], e.Data)
	}
	if err := x.bpfobjs.BpfMaps.TxOverrideMap.Put(&key, entrylist); err != nil {
		return fmt.Errorf("failed put tx override map: %w", err)
	}
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

func (x *Xdperf) initEbpfMap(entries []*TxOverrideEntry) error {
	if err := x.initSeqStateMap(); err != nil {
		x.Logger.Error("failed to init seq state map", zap.Error(err))
		return fmt.Errorf("failed to init seq state map: %w", err)
	}
	x.Logger.Info("seq state map initialized")

	if err := x.initTxOverrideMap(entries); err != nil {
		x.Logger.Error("failed to init tx override map", zap.Error(err))
		return fmt.Errorf("failed to init tx override map: %w", err)
	}
	x.Logger.Info("tx override map initialized")
	return nil
}
