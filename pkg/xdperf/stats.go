package xdperf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"golang.org/x/text/message"
)

type TrafficType string

const (
	TrafficTypeTX TrafficType = "tx"
	TrafficTypeRX TrafficType = "rx"
)

func (x *Xdperf) ShowStats(ctx context.Context, ty TrafficType) {
	var prevPackets uint64
	var prevBytes uint64
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var statMap *ebpf.Map
	showSuffix := ""
	switch ty {
	case TrafficTypeTX:
		statMap = x.bpfobjs.TxStatsMap
		showSuffix = "xmit"
	case TrafficTypeRX:
		statMap = x.bpfobjs.RxStatsMap
		showSuffix = "recv"
	default:
		fmt.Printf("unknown traffic type: %s\n", ty)
		return
	}
	for {
		select {
		case <-ticker.C:
			var key uint32
			err := statMap.Lookup(&key, &recs)
			if err != nil {
				fmt.Printf("failed to lookup stats_map: %v\n", err)
				continue
			}
			var sumPackets uint64
			var sumBytes uint64
			for _, rec := range recs {
				sumPackets += rec.Packets
				sumBytes += rec.Bytes
			}
			deltaPackets := sumPackets - prevPackets
			deltaBytes := sumBytes - prevBytes
			prevPackets = sumPackets
			prevBytes = sumBytes
			p.Printf("%d %s/s, %.2f Mbps\n", deltaPackets, showSuffix, float64(deltaBytes*8)/1024/1024)
		case <-ctx.Done():
			return
		}
	}
}
