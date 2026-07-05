package xdperf

import (
	"context"
	"math"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// statsTotals is a cumulative snapshot of one BPF stats map summed over CPUs.
type statsTotals struct {
	packets        uint64
	bytes          uint64
	diffErrors     uint64
	checksumErrors uint64
}

// metricsSource supplies the values observed by the OTLP export callback.
// A nil reader disables that group of instruments (e.g. rx is nil in
// client-only mode where the RX map is never updated).
type metricsSource struct {
	tx  func() (statsTotals, error)
	rx  func() (statsTotals, error)
	nic func() (NICStats, error)
}

// registerMetrics wires the BPF stats maps and NIC sysfs counters into
// ObservableCounters on meter. The SDK's PeriodicReader drives collection;
// no extra polling loop is needed, and nothing here is shared with the
// ShowStats display path.
func (x *Xdperf) registerMetrics(meter metric.Meter, ty TrafficType) error {
	src := metricsSource{}
	if ty == TrafficTypeTX || ty == TrafficTypeBoth {
		src.tx = x.statsReader(x.bpfobjs.TxStatsMap)
	}
	if ty == TrafficTypeRX || ty == TrafficTypeBoth {
		src.rx = x.statsReader(x.bpfobjs.RxStatsMap)
	}
	src.nic = func() (NICStats, error) {
		txPackets, err := x.readNICCounter("tx_packets")
		if err != nil {
			return NICStats{}, err
		}
		txDropped, err := x.readNICCounter("tx_dropped")
		if err != nil {
			return NICStats{}, err
		}
		return NICStats{TxXdpPackets: txPackets, TxXdpDropped: txDropped}, nil
	}
	return registerMetricsSource(meter, src, x.Logger)
}

func (x *Xdperf) statsReader(statMap *ebpf.Map) func() (statsTotals, error) {
	return func() (statsTotals, error) {
		// Buffer is local to each collection so it never races with the
		// ShowStats ticker; ebpf.Map.Lookup itself is concurrency-safe.
		recs := make([]coreelf.BpfDatarec, ebpf.MustPossibleCPU())
		packets, bytes, diffErrors, checksumErrors, err := sumStats(statMap, recs)
		if err != nil {
			return statsTotals{}, err
		}
		return statsTotals{packets: packets, bytes: bytes, diffErrors: diffErrors, checksumErrors: checksumErrors}, nil
	}
}

func registerMetricsSource(meter metric.Meter, src metricsSource, log *zap.Logger) error {
	packets, err := meter.Int64ObservableCounter("xdperf.packets",
		metric.WithUnit("{packet}"),
		metric.WithDescription("Packets processed by the XDP data plane"))
	if err != nil {
		return err
	}
	bytes, err := meter.Int64ObservableCounter("xdperf.bytes",
		metric.WithUnit("By"),
		metric.WithDescription("Bytes processed by the XDP data plane"))
	if err != nil {
		return err
	}
	errCounter, err := meter.Int64ObservableCounter("xdperf.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Packet generation errors in the XDP data plane"))
	if err != nil {
		return err
	}
	nicPackets, err := meter.Int64ObservableCounter("xdperf.nic.packets",
		metric.WithUnit("{packet}"),
		metric.WithDescription("NIC-level transmitted packets (may include other traffic on the same interface)"))
	if err != nil {
		return err
	}
	nicDropped, err := meter.Int64ObservableCounter("xdperf.nic.dropped",
		metric.WithUnit("{packet}"),
		metric.WithDescription("NIC-level dropped TX packets (may include other traffic on the same interface)"))
	if err != nil {
		return err
	}

	transmit := metric.WithAttributes(attribute.String("network.io.direction", "transmit"))
	receive := metric.WithAttributes(attribute.String("network.io.direction", "receive"))
	diffErr := metric.WithAttributes(attribute.String("error.type", "diff"))
	csumErr := metric.WithAttributes(attribute.String("error.type", "checksum"))

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		if src.tx != nil {
			if t, err := src.tx(); err != nil {
				log.Warn("failed to read TX stats for otlp metrics", zap.Error(err))
			} else {
				o.ObserveInt64(packets, clampToInt64(t.packets), transmit)
				o.ObserveInt64(bytes, clampToInt64(t.bytes), transmit)
				o.ObserveInt64(errCounter, clampToInt64(t.diffErrors), diffErr)
				o.ObserveInt64(errCounter, clampToInt64(t.checksumErrors), csumErr)
			}
		}
		if src.rx != nil {
			if r, err := src.rx(); err != nil {
				log.Warn("failed to read RX stats for otlp metrics", zap.Error(err))
			} else {
				o.ObserveInt64(packets, clampToInt64(r.packets), receive)
				o.ObserveInt64(bytes, clampToInt64(r.bytes), receive)
			}
		}
		if src.nic != nil {
			if n, err := src.nic(); err != nil {
				// Not all drivers expose these counters; skip rather than
				// report a bogus zero for a cumulative counter.
				log.Debug("failed to read NIC stats for otlp metrics", zap.Error(err))
			} else {
				o.ObserveInt64(nicPackets, clampToInt64(n.TxXdpPackets), transmit)
				o.ObserveInt64(nicDropped, clampToInt64(n.TxXdpDropped), transmit)
			}
		}
		return nil
	}, packets, bytes, errCounter, nicPackets, nicDropped)
	return err
}

// maxObservable is the saturation point for counter observations. The OTel
// API only accepts int64, and the SDK's sum aggregator additionally
// round-trips the value through float64 (atomicCounter.load), where a bare
// MaxInt64 rounds up to 2^63 and wraps to MinInt64. 2^63-1024 is the largest
// integer below MaxInt64 that float64 represents exactly.
const maxObservable = int64(math.MaxInt64) - 1023

// clampToInt64 saturates a uint64 counter at maxObservable so an
// (unrealistically) large counter can never surface as a negative value and
// break the monotonic sum.
func clampToInt64(v uint64) int64 {
	if v >= uint64(maxObservable) {
		return maxObservable
	}
	return int64(v)
}
