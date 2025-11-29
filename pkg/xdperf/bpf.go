package xdperf

import (
	"fmt"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

var _ = ebpf.PossibleCPU // keep import for initSeqStateMap

type TxOverrideEntry struct {
	Data   []byte
	Length uint16
}

// TX Override Map を初期化（PERCPU_ARRAY なので parallelism 分のCPUに書き込む）
func (x *Xdperf) initTxOverrideMap(entry []*TxOverrideEntry, parallelism int) error {
	if len(entry) == 0 {
		return fmt.Errorf("no entry")
	}

	numCpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed get possible CPU: %w", err)
	}

	for i, e := range entry {
		key := uint32(i)
		ld := int(e.Length)
		if ld <= 0 {
			return fmt.Errorf("invalid entry length: %d", e.Length)
		}
		if ld > len(e.Data) {
			return fmt.Errorf("length %d exceeds data size %d", e.Length, len(e.Data))
		}

		pktTemplate := coreelf.BpfPktTemplate{
			Len: uint32(e.Length),
		}
		copy(pktTemplate.Data[:], e.Data)

		// PERCPU_ARRAY: 全CPU分のスライスを作成し、parallelism分だけ値を設定
		templates := make([]coreelf.BpfPktTemplate, numCpus)
		for cpu := 0; cpu < parallelism && cpu < numCpus; cpu++ {
			templates[cpu] = pktTemplate
		}

		if err := x.bpfobjs.BpfMaps.TxOverrideMap.Put(&key, templates); err != nil {
			return fmt.Errorf("failed put tx override map at key %d: %w", i, err)
		}
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

func (x *Xdperf) initTemplateCountMap(count int) error {
	key := uint32(0)
	value := uint32(count)
	if err := x.bpfobjs.BpfMaps.TemplateCountMap.Put(&key, &value); err != nil {
		return fmt.Errorf("failed put template count map: %w", err)
	}
	return nil
}

func (x *Xdperf) initEbpfMap(entries []*TxOverrideEntry, parallelism int) error {
	if err := x.initSeqStateMap(); err != nil {
		x.Logger.Error("failed to init seq state map", zap.Error(err))
		return fmt.Errorf("failed to init seq state map: %w", err)
	}
	x.Logger.Info("seq state map initialized")

	if err := x.initTxOverrideMap(entries, parallelism); err != nil {
		x.Logger.Error("failed to init tx override map", zap.Error(err))
		return fmt.Errorf("failed to init tx override map: %w", err)
	}
	x.Logger.Info("tx override map initialized", zap.Int("entry_count", len(entries)), zap.Int("parallelism", parallelism))

	if err := x.initTemplateCountMap(len(entries)); err != nil {
		x.Logger.Error("failed to init template count map", zap.Error(err))
		return fmt.Errorf("failed to init template count map: %w", err)
	}
	x.Logger.Info("template count map initialized", zap.Int("count", len(entries)))

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
