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
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevTxPackets, prevTxBytes uint64
	var prevRxPackets, prevRxBytes uint64
	var prevDiffErrors, prevChecksumErrors uint64

	txStatsMap := x.bpfobjs.TxStatsMap

	for {
		select {
		case <-ticker.C:
			switch ty {
			case TrafficTypeTX:
				deltaPackets, deltaBytes, deltaDiffErr, deltaCsumErr := x.getStatsWithErrors(txStatsMap, recs, &prevTxPackets, &prevTxBytes, &prevDiffErrors, &prevChecksumErrors)
				x.recordPPSSample(deltaPackets)
				if deltaDiffErr > 0 || deltaCsumErr > 0 {
					p.Printf("%d xmit/s, %.2f Mbps (diff_err: %d, csum_err: %d)\n", deltaPackets, float64(deltaBytes*8)/1024/1024, deltaDiffErr, deltaCsumErr)
				} else {
					p.Printf("%d xmit/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
				}
			case TrafficTypeRX:
				deltaPackets, deltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				p.Printf("%d recv/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
			case TrafficTypeBoth:
				txDeltaPackets, txDeltaBytes, deltaDiffErr, deltaCsumErr := x.getStatsWithErrors(txStatsMap, recs, &prevTxPackets, &prevTxBytes, &prevDiffErrors, &prevChecksumErrors)
				x.recordPPSSample(txDeltaPackets)
				rxDeltaPackets, rxDeltaBytes := x.getStats(x.bpfobjs.RxStatsMap, recs, &prevRxPackets, &prevRxBytes)
				if deltaDiffErr > 0 || deltaCsumErr > 0 {
					p.Printf("%d xmit/s, %.2f Mbps(xmit) [diff_err: %d, csum_err: %d], %d recv/s, %.2f Mbps(recv)\n",
						txDeltaPackets, float64(txDeltaBytes*8)/1024/1024, deltaDiffErr, deltaCsumErr,
						rxDeltaPackets, float64(rxDeltaBytes*8)/1024/1024)
				} else {
					p.Printf("%d xmit/s, %.2f Mbps(xmit), %d recv/s, %.2f Mbps(recv)\n",
						txDeltaPackets, float64(txDeltaBytes*8)/1024/1024,
						rxDeltaPackets, float64(rxDeltaBytes*8)/1024/1024)
				}
			default:
				fmt.Printf("unknown traffic type: %s\n", ty)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// safeDelta returns cur-prev, or 0 if cur < prev (counter reset/wrap), avoiding
// unsigned-integer underflow that would otherwise produce a huge bogus delta.
func safeDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func (x *Xdperf) getStats(statMap *ebpf.Map, recs []coreelf.BpfDatarec, prevPackets, prevBytes *uint64) (deltaPackets, deltaBytes uint64) {
	// Reuse getStatsWithErrors and discard error counts
	var unusedDiffErrors, unusedChecksumErrors uint64
	deltaPackets, deltaBytes, _, _ = x.getStatsWithErrors(statMap, recs, prevPackets, prevBytes, &unusedDiffErrors, &unusedChecksumErrors)
	return deltaPackets, deltaBytes
}

// sumStats reads statMap and returns the cumulative per-CPU sums. recs is a
// caller-owned scratch buffer sized to the possible-CPU count.
func sumStats(statMap *ebpf.Map, recs []coreelf.BpfDatarec) (packets, bytes, diffErrors, checksumErrors uint64, err error) {
	var key uint32
	if err := statMap.Lookup(&key, &recs); err != nil {
		return 0, 0, 0, 0, err
	}
	for _, rec := range recs {
		packets += rec.Packets
		bytes += rec.Bytes
		diffErrors += rec.DiffErrors
		checksumErrors += rec.ChecksumErrors
	}
	return packets, bytes, diffErrors, checksumErrors, nil
}

func (x *Xdperf) getStatsWithErrors(statMap *ebpf.Map, recs []coreelf.BpfDatarec, prevPackets, prevBytes, prevDiffErrors, prevChecksumErrors *uint64) (deltaPackets, deltaBytes, deltaDiffErrors, deltaChecksumErrors uint64) {
	sumPackets, sumBytes, sumDiffErrors, sumChecksumErrors, err := sumStats(statMap, recs)
	if err != nil {
		fmt.Printf("failed to lookup stats_map: %v\n", err)
		return 0, 0, 0, 0
	}
	// Guard against unsigned underflow if a counter is reset (e.g. map re-init
	// or NIC counter wrap) between samples, which would otherwise report a huge
	// bogus delta.
	deltaPackets = safeDelta(sumPackets, *prevPackets)
	deltaBytes = safeDelta(sumBytes, *prevBytes)
	deltaDiffErrors = safeDelta(sumDiffErrors, *prevDiffErrors)
	deltaChecksumErrors = safeDelta(sumChecksumErrors, *prevChecksumErrors)
	*prevPackets = sumPackets
	*prevBytes = sumBytes
	*prevDiffErrors = sumDiffErrors
	*prevChecksumErrors = sumChecksumErrors
	return deltaPackets, deltaBytes, deltaDiffErrors, deltaChecksumErrors
}

// NICStats holds NIC-level statistics for XDP
type NICStats struct {
	TxXdpPackets uint64
	TxXdpDropped uint64
}

// readNICCounter reads a single counter from /sys/class/net/<device>/statistics/.
func (x *Xdperf) readNICCounter(name string) (uint64, error) {
	path := filepath.Join("/sys/class/net", x.Device.Name, "statistics", name)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read NIC stats %s: %w", path, err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse NIC stats %s: %w", path, err)
	}
	return v, nil
}

// GetNICStats reads XDP-related statistics from /sys/class/net/<device>/statistics/
func (x *Xdperf) GetNICStats() NICStats {
	var stats NICStats
	if v, err := x.readNICCounter("tx_packets"); err != nil {
		x.Logger.Debug("failed to read NIC stats", zap.Error(err))
	} else {
		stats.TxXdpPackets = v
	}
	if v, err := x.readNICCounter("tx_dropped"); err != nil {
		x.Logger.Debug("failed to read NIC stats", zap.Error(err))
	} else {
		stats.TxXdpDropped = v
	}
	return stats
}

// ShowFinalStats displays the final statistics after all packets have been sent.
func (x *Xdperf) ShowFinalStats(nicStatsBefore NICStats) {
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]coreelf.BpfDatarec, possibleCPUs)

	sumPackets, sumBytes, sumDiffErrors, sumChecksumErrors, err := sumStats(x.bpfobjs.TxStatsMap, recs)
	if err != nil {
		x.Logger.Error("failed to lookup stats_map", zap.Error(err))
		return
	}

	fields := []zap.Field{
		zap.Uint64("packets_processed", sumPackets),
		zap.Uint64("total_bytes", sumBytes),
		zap.Float64("total_megabytes", float64(sumBytes)/1024/1024),
	}
	if sumDiffErrors > 0 || sumChecksumErrors > 0 {
		fields = append(fields,
			zap.Uint64("diff_errors", sumDiffErrors),
			zap.Uint64("checksum_errors", sumChecksumErrors),
		)
	}
	x.Logger.Info("final statistics", fields...)

	// Pacing quality (PPS mode only records samples). The wakeup error is how
	// far past its scheduled point each batch started: the direct measure of
	// scheduling/timer jitter that --sched-policy and --scx aim to reduce.
	if s := x.pacing.summarize(); s.Count > 0 {
		x.Logger.Info("pacing statistics (batch wakeup error)",
			zap.Uint64("batches", s.Count),
			zap.Duration("p50", s.P50),
			zap.Duration("p99", s.P99),
			zap.Duration("max", s.Max),
		)
	}
	if st, ok := x.ppsStabilitySummary(); ok {
		x.Logger.Info("rate stability (per-second TX pps)",
			zap.Int("samples", st.Samples),
			zap.Float64("mean_pps", st.Mean),
			zap.Float64("stddev_pps", st.Stddev),
			zap.Float64("cv_percent", st.CV*100),
			zap.Uint64("min_pps", st.Min),
			zap.Uint64("max_pps", st.Max),
		)
	}

	// NIC statistics (only if flag is set)
	if x.cfg.ShowNICStats {
		nicStatsAfter := x.GetNICStats()
		nicTxDelta := safeDelta(nicStatsAfter.TxXdpPackets, nicStatsBefore.TxXdpPackets)
		nicDropDelta := safeDelta(nicStatsAfter.TxXdpDropped, nicStatsBefore.TxXdpDropped)

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
