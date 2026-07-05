// Package telemetry assembles the OpenTelemetry MeterProvider used for
// exporting xdperf statistics over OTLP/gRPC. It exists to keep the heavy
// otel SDK / gRPC dependencies out of pkg/xdperf; that package only needs
// the lightweight metric API returned by Setup.
package telemetry

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.uber.org/zap"
)

// MeterScope is the instrumentation scope name for all xdperf metrics.
const MeterScope = "github.com/takehaya/xdperf"

// shutdownTimeout bounds the final flush on Shutdown so an unreachable
// collector cannot hang process exit.
const shutdownTimeout = 5 * time.Second

type Config struct {
	Endpoint   string            // OTLP gRPC endpoint (host:port)
	Interval   time.Duration     // export interval for the PeriodicReader
	Insecure   bool              // use plaintext gRPC
	Attributes map[string]string // extra resource attributes
	Mode       string            // client / server / both
	Device     string            // network interface name
	Version    string            // xdperf version
}

// Setup builds an OTLP/gRPC MeterProvider and returns a Meter plus a shutdown
// function that performs the final flush. The exporter dials lazily, so Setup
// succeeds even when the collector is not reachable yet; export errors are
// reported through the zap-backed otel error handler instead.
func Setup(ctx context.Context, cfg Config, log *zap.Logger) (metric.Meter, func(context.Context) error, error) {
	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	// Extension point: an OTLP/HTTP exporter (otlpmetrichttp) can be swapped
	// in here if a --otlp-protocol flag ever becomes necessary.
	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP gRPC exporter: %w", err)
	}

	res, err := newResource(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build OTLP resource: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.Interval))
	provider := newProvider(reader, res)

	otel.SetErrorHandler(&zapErrorHandler{log: log})

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
		return provider.Shutdown(ctx)
	}
	return provider.Meter(MeterScope), shutdown, nil
}

// newProvider is split out so tests can inject a ManualReader.
func newProvider(reader sdkmetric.Reader, res *resource.Resource) *sdkmetric.MeterProvider {
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)
}

func newResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("xdperf"),
		attribute.String("xdperf.mode", cfg.Mode),
	}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.Version))
	}
	if cfg.Device != "" {
		attrs = append(attrs, semconv.NetworkInterfaceName(cfg.Device))
	}
	for k, v := range cfg.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	return resource.New(ctx,
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
}

// ParseAttributes parses a "key=value,key=value" flag string into a map.
// An empty string yields a nil map.
func ParseAttributes(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	attrs := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid attribute %q: expected key=value", pair)
		}
		attrs[k] = strings.TrimSpace(v)
	}
	return attrs, nil
}

// zapErrorHandler routes otel export errors to zap. Consecutive occurrences
// of the same error (e.g. a collector that stays down across export cycles)
// are demoted to Debug so they do not flood the log every interval.
type zapErrorHandler struct {
	log  *zap.Logger
	mu   sync.Mutex
	last string
}

func (h *zapErrorHandler) Handle(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	h.mu.Lock()
	repeated := msg == h.last
	h.last = msg
	h.mu.Unlock()
	if repeated {
		h.log.Debug("otlp metrics export error (repeated)", zap.Error(err))
		return
	}
	h.log.Warn("otlp metrics export error", zap.Error(err))
}
