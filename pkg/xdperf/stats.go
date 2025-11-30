package xdperf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
				if x.cfg.PPS > 0 {
					achievedRatio := float64(deltaPackets) / float64(x.cfg.PPS) * 100
					p.Printf("%d xmit/s (%.1f%% of target %d), %.2f Mbps\n",
						deltaPackets, achievedRatio, x.cfg.PPS, float64(deltaBytes*8)/1024/1024)
				} else {
					p.Printf("%d xmit/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
				}
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

// NICStats holds NIC-level statistics for XDP
type NICStats struct {
	TxXdpPackets uint64
	TxXdpDropped uint64
}

// GetNICStats reads XDP-related statistics from /sys/class/net/<device>/statistics/
func (x *Xdperf) GetNICStats() NICStats {
	var stats NICStats
	basePath := filepath.Join("/sys/class/net", x.Device.Name, "statistics")

	// Read tx_packets
	if data, err := os.ReadFile(filepath.Join(basePath, "tx_packets")); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.TxXdpPackets = v
		}
	}

	// Read tx_dropped
	if data, err := os.ReadFile(filepath.Join(basePath, "tx_dropped")); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.TxXdpDropped = v
		}
	}

	return stats
}

// ShowFinalStats displays the final statistics after all packets have been sent.
func (x *Xdperf) ShowFinalStats(nicStatsBefore NICStats) {
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)
	p := message.NewPrinter(message.MatchLanguage("en"))

	var key uint32
	err := x.bpfobjs.TxStatsMap.Lookup(&key, &recs)
	if err != nil {
		fmt.Printf("failed to lookup stats_map: %v\n", err)
		return
	}
	var sumPackets uint64
	var sumBytes uint64
	for _, rec := range recs {
		sumPackets += rec.Packets
		sumBytes += rec.Bytes
	}

	// Get NIC stats after
	nicStatsAfter := x.GetNICStats()
	nicTxDelta := nicStatsAfter.TxXdpPackets - nicStatsBefore.TxXdpPackets
	nicDropDelta := nicStatsAfter.TxXdpDropped - nicStatsBefore.TxXdpDropped

	p.Printf("\n=== Final Statistics ===\n")
	p.Printf("Packets processed by XDP: %d\n", sumPackets)
	p.Printf("NIC TX packets: %d\n", nicTxDelta)
	if nicDropDelta > 0 {
		p.Printf("NIC TX dropped: %d\n", nicDropDelta)
	}

	// Calculate actual drop rate based on XDP processed vs NIC TX
	if sumPackets > nicTxDelta {
		droppedPackets := sumPackets - nicTxDelta
		dropRate := float64(droppedPackets) / float64(sumPackets) * 100
		p.Printf("XDP->NIC dropped: %d (%.1f%%)\n", droppedPackets, dropRate)
	}

	p.Printf("Total bytes: %d (%.2f MB)\n", sumBytes, float64(sumBytes)/1024/1024)
}
