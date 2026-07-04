package xdperf

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
	"go.uber.org/zap"
)

func collectMetrics(t *testing.T, src metricsSource) metricdata.ScopeMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	meter := provider.Meter("test")
	if err := registerMetricsSource(meter, src, zap.NewNop()); err != nil {
		t.Fatalf("registerMetricsSource() error = %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(rm.ScopeMetrics) != 1 {
		t.Fatalf("got %d scope metrics, want 1", len(rm.ScopeMetrics))
	}
	return rm.ScopeMetrics[0]
}

func findMetric(t *testing.T, sm metricdata.ScopeMetrics, name string) (metricdata.Metrics, bool) {
	t.Helper()
	for _, m := range sm.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return metricdata.Metrics{}, false
}

func transmitAttr() attribute.Set {
	return attribute.NewSet(attribute.String("network.io.direction", "transmit"))
}

func receiveAttr() attribute.Set {
	return attribute.NewSet(attribute.String("network.io.direction", "receive"))
}

func TestRegisterMetricsSourceBothMode(t *testing.T) {
	src := metricsSource{
		tx: func() (statsTotals, error) {
			return statsTotals{packets: 1000, bytes: 64000, diffErrors: 3, checksumErrors: 1}, nil
		},
		rx: func() (statsTotals, error) {
			return statsTotals{packets: 900, bytes: 57600}, nil
		},
		nic: func() (NICStats, error) {
			return NICStats{TxXdpPackets: 990, TxXdpDropped: 10}, nil
		},
	}
	sm := collectMetrics(t, src)

	wantPackets := metricdata.Metrics{
		Name:        "xdperf.packets",
		Unit:        "{packet}",
		Description: "Packets processed by the XDP data plane",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints: []metricdata.DataPoint[int64]{
				{Attributes: transmitAttr(), Value: 1000},
				{Attributes: receiveAttr(), Value: 900},
			},
		},
	}
	got, ok := findMetric(t, sm, "xdperf.packets")
	if !ok {
		t.Fatal("xdperf.packets not found")
	}
	metricdatatest.AssertEqual(t, wantPackets, got, metricdatatest.IgnoreTimestamp())

	wantErrors := metricdata.Metrics{
		Name:        "xdperf.errors",
		Unit:        "{error}",
		Description: "Packet generation errors in the XDP data plane",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints: []metricdata.DataPoint[int64]{
				{Attributes: attribute.NewSet(attribute.String("error.type", "diff")), Value: 3},
				{Attributes: attribute.NewSet(attribute.String("error.type", "checksum")), Value: 1},
			},
		},
	}
	got, ok = findMetric(t, sm, "xdperf.errors")
	if !ok {
		t.Fatal("xdperf.errors not found")
	}
	metricdatatest.AssertEqual(t, wantErrors, got, metricdatatest.IgnoreTimestamp())

	wantNicDropped := metricdata.Metrics{
		Name:        "xdperf.nic.dropped",
		Unit:        "{packet}",
		Description: "NIC-level dropped TX packets (may include other traffic on the same interface)",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints: []metricdata.DataPoint[int64]{
				{Attributes: transmitAttr(), Value: 10},
			},
		},
	}
	got, ok = findMetric(t, sm, "xdperf.nic.dropped")
	if !ok {
		t.Fatal("xdperf.nic.dropped not found")
	}
	metricdatatest.AssertEqual(t, wantNicDropped, got, metricdatatest.IgnoreTimestamp())

	if _, ok := findMetric(t, sm, "xdperf.bytes"); !ok {
		t.Error("xdperf.bytes not found")
	}
	if _, ok := findMetric(t, sm, "xdperf.nic.packets"); !ok {
		t.Error("xdperf.nic.packets not found")
	}
}

func TestRegisterMetricsSourceRXOnly(t *testing.T) {
	src := metricsSource{
		rx: func() (statsTotals, error) {
			return statsTotals{packets: 42, bytes: 2688}, nil
		},
	}
	sm := collectMetrics(t, src)

	got, ok := findMetric(t, sm, "xdperf.packets")
	if !ok {
		t.Fatal("xdperf.packets not found")
	}
	sum, ok := got.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("xdperf.packets data type = %T, want Sum[int64]", got.Data)
	}
	if len(sum.DataPoints) != 1 {
		t.Fatalf("got %d data points, want 1 (receive only)", len(sum.DataPoints))
	}
	if dir, _ := sum.DataPoints[0].Attributes.Value("network.io.direction"); dir.AsString() != "receive" {
		t.Errorf("direction = %q, want receive", dir.AsString())
	}

	// TX-only instruments must have no data points when tx is nil.
	if m, ok := findMetric(t, sm, "xdperf.errors"); ok {
		if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) > 0 {
			t.Errorf("xdperf.errors has %d data points, want 0 in RX-only mode", len(sum.DataPoints))
		}
	}
}

func TestRegisterMetricsSourceSkipsFailedReads(t *testing.T) {
	src := metricsSource{
		tx: func() (statsTotals, error) {
			return statsTotals{packets: 10, bytes: 640}, nil
		},
		nic: func() (NICStats, error) {
			return NICStats{}, errors.New("sysfs not available")
		},
	}
	sm := collectMetrics(t, src)

	// TX observations must survive a failing NIC reader.
	got, ok := findMetric(t, sm, "xdperf.packets")
	if !ok {
		t.Fatal("xdperf.packets not found")
	}
	sum := got.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 10 {
		t.Errorf("unexpected xdperf.packets data points: %+v", sum.DataPoints)
	}

	// NIC metrics must not report a bogus zero on read failure.
	if m, ok := findMetric(t, sm, "xdperf.nic.packets"); ok {
		if sum, ok := m.Data.(metricdata.Sum[int64]); ok && len(sum.DataPoints) > 0 {
			t.Errorf("xdperf.nic.packets has %d data points, want 0 on read failure", len(sum.DataPoints))
		}
	}
}
