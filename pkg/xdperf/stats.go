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
	TrafficTypeTX   TrafficType = "tx"
	TrafficTypeRX   TrafficType = "rx"
	TrafficTypeBoth TrafficType = "both"
)

func (x *Xdperf) ShowStats(ctx context.Context, ty TrafficType) {
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevTxPackets, prevTxBytes uint64
	var prevRxPackets, prevRxBytes uint64

	for {
		select {
		case <-ticker.C:
			switch ty {
			case TrafficTypeTX:
				deltaPackets, deltaBytes := x.getStats(x.bpfobjs.TxStatsMap, recs, &prevTxPackets, &prevTxBytes)
				p.Printf("%d xmit/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
			case TrafficTypeRX:
				deltaPackets, deltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				p.Printf("%d recv/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
			case TrafficTypeBoth:
				txDeltaPackets, txDeltaBytes := x.getStats(x.bpfobjs.TxStatsMap, recs, &prevTxPackets, &prevTxBytes)
				rxDeltaPackets, rxDeltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				p.Printf("%d xmit/s, %.2f Mbps(xmit), %d recv/s, %.2f Mbps(recv)\n",
					txDeltaPackets, float64(txDeltaBytes*8)/1024/1024,
					rxDeltaPackets, float64(rxDeltaBytes*8)/1024/1024)
			default:
				fmt.Printf("unknown traffic type: %s\n", ty)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (x *Xdperf) getStats(statMap *ebpf.Map, recs []coreelf.BpfDatarec, prevPackets, prevBytes *uint64) (deltaPackets, deltaBytes uint64) {
	var key uint32
	err := statMap.Lookup(&key, &recs)
	if err != nil {
		fmt.Printf("failed to lookup stats_map: %v\n", err)
		return 0, 0
	}
	var sumPackets uint64
	var sumBytes uint64
	for _, rec := range recs {
		sumPackets += rec.Packets
		sumBytes += rec.Bytes
	}
	deltaPackets = sumPackets - *prevPackets
	deltaBytes = sumBytes - *prevBytes
	*prevPackets = sumPackets
	*prevBytes = sumBytes
	return deltaPackets, deltaBytes
}
