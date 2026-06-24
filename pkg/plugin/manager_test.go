package plugin

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestNewManagerRegistersHostFunctions exercises registerHostAPIFunctions, which
// instantiates the "env" host module and thereby validates the host_log /
// host_report_metric closure signatures (makeLogFunc / makeMetricFunc). A
// signature mismatch would fail here at Instantiate time.
func TestNewManagerRegistersHostFunctions(t *testing.T) {
	m, err := NewManager(t.TempDir(), "", "tinygo", WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if m.logger == nil {
		t.Error("expected logger to be set from WithLogger")
	}
}

// TestNewManagerNilLoggerDefaultsToNop verifies the manager tolerates an unset
// logger (host log/metric calls must not nil-panic).
func TestNewManagerNilLoggerDefaultsToNop(t *testing.T) {
	m, err := NewManager(t.TempDir(), "", "tinygo")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if m.logger == nil {
		t.Error("expected nil logger to default to a no-op logger")
	}
}
