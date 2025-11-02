package xdperf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"golang.org/x/text/message"
)

func (x *Xdperf) ShowStats(ctx context.Context) {
	var prevPackets uint64
	var prevBytes uint64
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var key uint32
			err := x.bpfobjs.StatsMap.Lookup(&key, &recs)
			if err != nil {
				fmt.Printf("failed to lookup stats_map: %v\n", err)
				continue
			}
			var sumPackets uint64
			var sumBytes uint64
			for _, rec := range recs {
				sumPackets += rec.RxPackets
				sumBytes += rec.RxBytes
			}
			deltaPackets := sumPackets - prevPackets
			deltaBytes := sumBytes - prevBytes
			prevPackets = sumPackets
			prevBytes = sumBytes
			p.Printf("%d xmit/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
		case <-ctx.Done():
			return
		}
	}
}
