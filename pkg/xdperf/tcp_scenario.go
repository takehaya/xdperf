package xdperf

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"
	"unicode"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/plugin"
	"go.uber.org/zap"
)

func tcpScenarioRequest(c Config) (guest.TCPScenarioRequest, error) {
	config := json.RawMessage(`{}`)
	if c.PluginConfig != "" {
		// Validate the object without converting plugin-owned numbers to float64.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(c.PluginConfig), &fields); err != nil {
			return guest.TCPScenarioRequest{}, fmt.Errorf("invalid plugin config: %w", err)
		}
		config = json.RawMessage(c.PluginConfig)
	}
	return guest.TCPScenarioRequest{
		Mode: "tcp_scenario", SupportedVersions: []int{1},
		Capabilities: []string{"static_flows", "zero_payload"},
		DeviceName:   c.Device,
		Limits:       guest.TCPScenarioLimits{MaxSlots: 65536 - c.TCPPortBase, MaxEndpoints: 1, MaxResponseBytes: plugin.MaxPluginOutputBytes},
		Config:       config,
	}, nil
}

func (x *Xdperf) loadTCPScenario(ctx context.Context) error {
	// All guest execution finishes before target resolution, map initialization,
	// XDP attachment and workers. A canceled call closes the Wasm module.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := tcpScenarioRequest(x.cfg)
	if err != nil {
		return err
	}
	wp, err := x.PluginManager.GetPlugin(x.cfg.PluginName)
	if err != nil {
		return err
	}
	gen := plugin.NewGeneratorAdapter(x.cfg.PluginName, wp)
	initJSON, err := json.Marshal(guest.GeneratorInitRequest{PluginConfig: []byte(x.cfg.PluginConfig)})
	if err != nil {
		return err
	}
	out, err := gen.Initialize(ctx, initJSON)
	if err != nil {
		return fmt.Errorf("TCP scenario init: %w", err)
	}
	var initialized guest.GeneratorInitResponse
	if err := json.Unmarshal(out, &initialized); err != nil {
		return fmt.Errorf("TCP scenario init response: %w", err)
	}
	if !initialized.Success {
		return fmt.Errorf("TCP scenario plugin initialization failed")
	}
	s, err := gen.GenerateTCPScenario(ctx, req)
	if err != nil {
		return fmt.Errorf("TCP scenario process: %w", err)
	}
	if err := x.applyTCPScenario(s); err != nil {
		return err
	}
	x.Logger.Info("TCP scenario loaded", zap.String("scenario_id", s.ScenarioID), zap.String("seed", s.Seed), zap.Int("flows", len(s.Flows)))
	return nil
}

// decimalUint64 deliberately rejects signs, exponents and whitespace.
func decimalUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("expected a uint64 decimal string")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("expected a uint64 decimal string, got %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func validScenarioID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return false
		}
	}
	return true
}

// applyTCPScenario validates the complete plan before changing host config.
// Definition order is the stable mapping to CSV flow and tcp_flow_map indices.
func (x *Xdperf) applyTCPScenario(s *guest.TCPScenario) error {
	if s == nil || s.Version != 1 {
		return fmt.Errorf("TCP scenario requires version 1")
	}
	for _, capability := range s.Requires {
		if capability != "static_flows" && capability != "zero_payload" {
			return fmt.Errorf("unsupported TCP scenario capability %q", capability)
		}
	}
	if !validScenarioID(s.ScenarioID) {
		return fmt.Errorf("scenario_id must be 1..128 bytes without whitespace or control characters")
	}
	if _, err := decimalUint64(s.Seed); err != nil {
		return fmt.Errorf("scenario seed: %w", err)
	}
	if len(s.Endpoints) != 1 {
		return fmt.Errorf("TCP scenario requires exactly one endpoint")
	}
	ep := s.Endpoints[0]
	if !validScenarioID(ep.ID) || net.ParseIP(ep.Address) == nil || ep.Port < 1 || ep.Port > 65535 {
		return fmt.Errorf("invalid TCP scenario endpoint (ID, IP literal and port 1..65535 required)")
	}
	if len(s.Payloads) != 1 || !validScenarioID(s.Payloads[0].ID) || s.Payloads[0].Kind != "zero" {
		return fmt.Errorf("TCP scenario requires exactly one zero payload")
	}
	capacity := 65536 - x.cfg.TCPPortBase
	if x.cfg.TCPPortBase < 1 || x.cfg.TCPPortBase > 65535 || len(s.Flows) == 0 || len(s.Flows) > capacity {
		return fmt.Errorf("TCP scenario flows exceed the available source port range or are empty")
	}
	if s.MaxActive < len(s.Flows) || s.MaxActive > capacity {
		return fmt.Errorf("TCP scenario max_active must be between flow count (%d) and available slots (%d)", len(s.Flows), capacity)
	}
	duration := x.cfg.Duration
	if s.DurationNS != "" {
		ns, err := decimalUint64(s.DurationNS)
		if err != nil || ns == 0 || ns > math.MaxInt64 {
			return fmt.Errorf("scenario duration_ns must be a positive decimal string <= %d", int64(math.MaxInt64))
		}
		if duration == 0 || time.Duration(ns) < duration {
			duration = time.Duration(ns)
		}
	}
	ids := make(map[string]bool, len(s.Flows))
	targets := make([]uint64, len(s.Flows))
	for i, f := range s.Flows {
		if !validScenarioID(f.ID) || ids[f.ID] {
			return fmt.Errorf("flow %d: invalid or duplicate ID %q", i, f.ID)
		}
		ids[f.ID] = true
		if f.Endpoint != ep.ID || f.Payload != s.Payloads[0].ID {
			return fmt.Errorf("flow %q: undefined endpoint or payload", f.ID)
		}
		start, err := decimalUint64(f.StartNS)
		if err != nil || start != 0 {
			return fmt.Errorf("flow %q: start_ns must be the decimal string zero (scheduled flows are unsupported)", f.ID)
		}
		n, err := decimalUint64(f.Bytes)
		if err != nil {
			return fmt.Errorf("flow %q bytes: %w", f.ID, err)
		}
		if n == 0 && duration <= 0 {
			return fmt.Errorf("flow %q: unlimited bytes requires duration_ns or --duration", f.ID)
		}
		targets[i] = n
	}
	x.cfg.TCPDst = net.JoinHostPort(ep.Address, strconv.Itoa(ep.Port))
	x.cfg.TCPFlows = len(s.Flows)
	x.cfg.TCPBytes = 0 // bytes_target in each flow is authoritative.
	x.cfg.Duration = duration
	x.tcpScenarioBytes = targets
	return nil
}
