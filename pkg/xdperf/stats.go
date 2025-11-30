package xdperf

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
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
					x.Logger.Info("stats",
						zap.Uint64("xmit_per_sec", deltaPackets),
						zap.Float64("achieved_ratio_percent", achievedRatio),
						zap.Uint64("target_pps", x.cfg.PPS),
						zap.Float64("mbps", float64(deltaBytes*8)/1024/1024),
					)
				} else {
					x.Logger.Info("stats",
						zap.Uint64("xmit_per_sec", deltaPackets),
						zap.Float64("mbps", float64(deltaBytes*8)/1024/1024),
					)
				}
			case TrafficTypeRX:
				deltaPackets, deltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				x.Logger.Info("stats",
					zap.Uint64("recv_per_sec", deltaPackets),
					zap.Float64("mbps", float64(deltaBytes*8)/1024/1024),
				)
			case TrafficTypeBoth:
				txDeltaPackets, txDeltaBytes := x.getStats(x.bpfobjs.TxStatsMap, recs, &prevTxPackets, &prevTxBytes)
				rxDeltaPackets, rxDeltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				x.Logger.Info("stats",
					zap.Uint64("xmit_per_sec", txDeltaPackets),
					zap.Float64("mbps_xmit", float64(txDeltaBytes*8)/1024/1024),
					zap.Uint64("recv_per_sec", rxDeltaPackets),
					zap.Float64("mbps_recv", float64(rxDeltaBytes*8)/1024/1024),
				)
			default:
				x.Logger.Error("unknown traffic type", zap.String("type", string(ty)))
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
		x.Logger.Error("failed to lookup stats_map", zap.Error(err))
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
	txPacketsPath := filepath.Join(basePath, "tx_packets")
	if data, err := os.ReadFile(txPacketsPath); err != nil {
		x.Logger.Debug("failed to read NIC stats", zap.String("path", txPacketsPath), zap.Error(err))
	} else {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
			x.Logger.Debug("failed to parse NIC stats", zap.String("path", txPacketsPath), zap.Error(err))
		} else {
			stats.TxXdpPackets = v
		}
	}

	// Read tx_dropped
	txDroppedPath := filepath.Join(basePath, "tx_dropped")
	if data, err := os.ReadFile(txDroppedPath); err != nil {
		x.Logger.Debug("failed to read NIC stats", zap.String("path", txDroppedPath), zap.Error(err))
	} else {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
			x.Logger.Debug("failed to parse NIC stats", zap.String("path", txDroppedPath), zap.Error(err))
		} else {
			stats.TxXdpDropped = v
		}
	}

	return stats
}

// ShowFinalStats displays the final statistics after all packets have been sent.
func (x *Xdperf) ShowFinalStats(nicStatsBefore NICStats) {
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)

	var key uint32
	err := x.bpfobjs.TxStatsMap.Lookup(&key, &recs)
	if err != nil {
		x.Logger.Error("failed to lookup stats_map", zap.Error(err))
		return
	}
	var sumPackets uint64
	var sumBytes uint64
	for _, rec := range recs {
		sumPackets += rec.Packets
		sumBytes += rec.Bytes
	}

	x.Logger.Info("final statistics",
		zap.Uint64("packets_processed", sumPackets),
		zap.Uint64("total_bytes", sumBytes),
		zap.Float64("total_megabytes", float64(sumBytes)/1024/1024),
	)

	// NIC statistics (only if flag is set)
	if x.cfg.ShowNICStats {
		nicStatsAfter := x.GetNICStats()
		nicTxDelta := nicStatsAfter.TxXdpPackets - nicStatsBefore.TxXdpPackets
		nicDropDelta := nicStatsAfter.TxXdpDropped - nicStatsBefore.TxXdpDropped

		fields := []zap.Field{
			zap.Uint64("nic_tx_packets", nicTxDelta),
			zap.Uint64("nic_tx_dropped", nicDropDelta),
		}

		// Calculate actual drop rate based on XDP processed vs NIC TX
		if sumPackets > nicTxDelta {
			droppedPackets := sumPackets - nicTxDelta
			dropRate := float64(droppedPackets) / float64(sumPackets) * 100
			fields = append(fields,
				zap.Uint64("xdp_to_nic_dropped", droppedPackets),
				zap.Float64("drop_rate_percent", dropRate),
			)
		}

		x.Logger.Info("NIC statistics (may include other traffic on the same interface)", fields...)
	}
}
