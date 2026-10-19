package xdperf

import (
	"encoding/json"
	"math"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

func testTCPScenario() *guest.TCPScenario {
	return &guest.TCPScenario{
		Version: 1, ScenarioID: "heavy-hitter-4", Seed: "42", MaxActive: 4,
		Requires:  []string{"static_flows", "zero_payload"},
		Endpoints: []guest.TCPScenarioEndpoint{{ID: "sink", Address: "192.0.2.2", Port: 5201}},
		Payloads:  []guest.TCPScenarioPayload{{ID: "zero", Kind: "zero"}},
		Flows: []guest.TCPScenarioFlow{
			{ID: "f0", Endpoint: "sink", Payload: "zero", Bytes: "65536", StartNS: "0"},
			{ID: "f1", Endpoint: "sink", Payload: "zero", Bytes: "65536", StartNS: "0"},
			{ID: "f2", Endpoint: "sink", Payload: "zero", Bytes: "65536", StartNS: "0"},
			{ID: "f3", Endpoint: "sink", Payload: "zero", Bytes: "67108864", StartNS: "0"},
		},
	}
}

func TestApplyTCPScenarioRejectsInvalid(t *testing.T) {
	cases := map[string]func(*guest.TCPScenario){
		"version":            func(s *guest.TCPScenario) { s.Version = 2 },
		"capability":         func(s *guest.TCPScenario) { s.Requires = []string{"slot_reuse"} },
		"scenario ID":        func(s *guest.TCPScenario) { s.ScenarioID = "" },
		"long ID":            func(s *guest.TCPScenario) { s.Flows[0].ID = strings.Repeat("x", 129) },
		"duplicate flow":     func(s *guest.TCPScenario) { s.Flows[1].ID = "f0" },
		"seed":               func(s *guest.TCPScenario) { s.Seed = "-1" },
		"empty flows":        func(s *guest.TCPScenario) { s.Flows = nil },
		"too many flows":     func(s *guest.TCPScenario) { s.Flows = make([]guest.TCPScenarioFlow, 65536) },
		"max active low":     func(s *guest.TCPScenario) { s.MaxActive = 3 },
		"max active high":    func(s *guest.TCPScenario) { s.MaxActive = 65536 },
		"no endpoint":        func(s *guest.TCPScenario) { s.Endpoints = nil },
		"multiple endpoints": func(s *guest.TCPScenario) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) },
		"hostname":           func(s *guest.TCPScenario) { s.Endpoints[0].Address = "localhost" },
		"zero port":          func(s *guest.TCPScenario) { s.Endpoints[0].Port = 0 },
		"large port":         func(s *guest.TCPScenario) { s.Endpoints[0].Port = 65536 },
		"endpoint ref":       func(s *guest.TCPScenario) { s.Flows[0].Endpoint = "unknown" },
		"payload ref":        func(s *guest.TCPScenario) { s.Flows[0].Payload = "unknown" },
		"no payload":         func(s *guest.TCPScenario) { s.Payloads = nil },
		"nonzero payload":    func(s *guest.TCPScenario) { s.Payloads[0].Kind = "prefix_zero" },
		"scheduled":          func(s *guest.TCPScenario) { s.Flows[0].StartNS = "1" },
		"missing start":      func(s *guest.TCPScenario) { s.Flows[0].StartNS = "" },
		"unlimited":          func(s *guest.TCPScenario) { s.Flows[0].Bytes = "0" },
		"missing bytes":      func(s *guest.TCPScenario) { s.Flows[0].Bytes = "" },
		"negative":           func(s *guest.TCPScenario) { s.Flows[0].Bytes = "-1" },
		"plus":               func(s *guest.TCPScenario) { s.Flows[0].Bytes = "+1" },
		"exponent":           func(s *guest.TCPScenario) { s.Flows[0].Bytes = "1e6" },
		"whitespace":         func(s *guest.TCPScenario) { s.Flows[0].Bytes = " 1" },
		"overflow":           func(s *guest.TCPScenario) { s.Flows[0].Bytes = "18446744073709551616" },
		"duration overflow":  func(s *guest.TCPScenario) { s.DurationNS = "9223372036854775808" },
		"duration zero":      func(s *guest.TCPScenario) { s.DurationNS = "0" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := testTCPScenario()
			mutate(s)
			x := &Xdperf{cfg: tcpTestConfig()}
			before := x.cfg
			if err := x.applyTCPScenario(s); err == nil {
				t.Fatal("accepted invalid scenario")
			}
			if !reflect.DeepEqual(before, x.cfg) || x.tcpScenarioBytes != nil {
				t.Fatal("failed validation mutated config")
			}
		})
	}
}

func TestApplyTCPScenario(t *testing.T) {
	x := &Xdperf{cfg: tcpTestConfig()}
	s := testTCPScenario()
	s.Endpoints[0].Address = "2001:db8::2"
	s.Flows[0].Bytes = "18446744073709551615"
	if err := x.applyTCPScenario(s); err != nil {
		t.Fatal(err)
	}
	if x.cfg.TCPDst != "[2001:db8::2]:5201" || x.cfg.TCPFlows != 4 || x.tcpScenarioBytes[0] != math.MaxUint64 {
		t.Fatalf("unexpected config: %+v", x.cfg)
	}
	for _, cliDuration := range []time.Duration{0, time.Second, 3 * time.Second} {
		x.cfg.Duration = cliDuration
		s.DurationNS = "2000000000"
		s.Flows[0].Bytes = "0"
		if err := x.applyTCPScenario(s); err != nil {
			t.Fatal(err)
		}
		want := 2 * time.Second
		if cliDuration == time.Second {
			want = time.Second
		}
		if x.cfg.Duration != want {
			t.Fatalf("duration = %v, want %v", x.cfg.Duration, want)
		}
	}
	x.cfg.Duration = time.Second
	s.DurationNS = ""
	if err := x.applyTCPScenario(s); err != nil {
		t.Fatal(err)
	}
}

func TestTCPScenarioConfig(t *testing.T) {
	c := tcpTestConfig()
	c.TCPDst, c.TCPBytes, c.TCPFlows = "", 0, 1
	c.PluginName = "heavyhitter.go"
	c.Normalize()
	if c.PluginLanguage != "go" {
		t.Fatal("missing Go language inference")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.TCPDst = "192.0.2.1:5201" },
		func(c *Config) { c.TCPBytes = 1 },
		func(c *Config) { c.TCPFlows = 4 },
		func(c *Config) { c.TCPPortBase = 65536 },
	} {
		invalid := c
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("accepted conflicting config")
		}
	}
	c.TCPPortBase = 65532
	r, err := tcpScenarioRequest(c)
	if err != nil || r.Limits.MaxSlots != 4 {
		t.Fatalf("request = %+v, err = %v", r, err)
	}
}

// Exercise the actual BTF-backed, spin-locked flow map, including CPU ownership.
func TestTCPScenarioMaps(t *testing.T) {
	objs, _, err := coreelf.ReadCollectionWithSizes(map[string]any{"swap_resp": uint32(0)}, map[string]uint32{"diff_map": 1, "tcp_srv_flow_map": 1})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	target := &tcpTarget{srcIP: net.ParseIP("192.0.2.1").To4(), dstIP: net.ParseIP("192.0.2.2").To4(), srcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, dstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, ipVersion: 4, mss: 1024, dstPort: 5201, l3Off: 14, l4Off: 34, hdrLen: 54}
	template, err := buildTCPTemplate(target, uint16(tcpTestConfig().TCPPortBase))
	if err != nil {
		t.Fatal(err)
	}
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	workers := []struct {
		name   string
		cpus   []int
		states []coreelf.BpfTcpCpuState
	}{
		{"single worker", []int{0}, []coreelf.BpfTcpCpuState{{First: 0, Stride: 1, Count: 4}}},
		{"two workers", []int{0, 1}, []coreelf.BpfTcpCpuState{{First: 0, Stride: 2, Count: 2}, {First: 1, Stride: 2, Count: 2}}},
	}
	mixed := testTCPScenario()
	mixed.DurationNS = "1000000000"
	for i, n := range []string{"0", "9007199254740993", "18446744073709551615", "65537"} {
		mixed.Flows[i].Bytes = n
	}
	cases := []struct {
		name         string
		scenario     *guest.TCPScenario
		targets      []uint64
		bytesPerFlow uint64
	}{
		{"legacy", nil, []uint64{1000, 1000, 1000, 1000}, 1000},
		{"heavy hitter", testTCPScenario(), []uint64{65536, 65536, 65536, 67108864}, 0},
		{"mixed boundaries", mixed, []uint64{0, 1<<53 + 1, math.MaxUint64, 65537}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, worker := range workers {
				t.Run(worker.name, func(t *testing.T) {
					if len(worker.cpus) > numCPU {
						t.Skip("two possible CPUs are required for the ownership test")
					}
					x := &Xdperf{cfg: tcpTestConfig(), bpfobjs: objs, cpus: worker.cpus, Logger: zap.NewNop()}
					if tc.scenario != nil {
						x.cfg.TCPFlows = 1
						if err := x.applyTCPScenario(tc.scenario); err != nil {
							t.Fatal(err)
						}
					}
					if err := x.initTCPMaps(target, template); err != nil {
						t.Fatal(err)
					}
					flows, err := x.readTCPFlows(len(tc.targets))
					if err != nil {
						t.Fatal(err)
					}
					for i, f := range flows {
						if f.BytesTarget != tc.targets[i] || f.SrcPort != uint16(x.cfg.TCPPortBase+i) || f.State != tcpFlowClosed || f.TxData != 0 {
							t.Fatalf("flow %d = %+v, target %d", i, f, tc.targets[i])
						}
					}
					var cfg coreelf.BpfTcpCfg
					key := uint32(0)
					if err := objs.TcpCfgMap.Lookup(&key, &cfg); err != nil {
						t.Fatal(err)
					}
					if cfg.FlowCount != 4 || cfg.DstPort != 5201 || cfg.BytesPerFlow != tc.bytesPerFlow {
						t.Fatalf("cfg = %+v, want bytes_per_flow %d", cfg, tc.bytesPerFlow)
					}
					states := make([]coreelf.BpfTcpCpuState, numCPU)
					if err := objs.TcpCpuStateMap.Lookup(&key, &states); err != nil {
						t.Fatal(err)
					}
					for cpu, state := range states {
						want := coreelf.BpfTcpCpuState{}
						if cpu < len(worker.states) {
							want = worker.states[cpu]
						}
						if state != want {
							t.Fatalf("CPU %d state = %+v, want %+v", cpu, state, want)
						}
					}
				})
			}
		})
	}
}

func TestTCPScenarioConfigPreservesJSON(t *testing.T) {
	c := tcpTestConfig()
	c.PluginConfig = `{"custom_id":9007199254740993,"nested":{"n":18446744073709551615}}`
	req, err := tcpScenarioRequest(c)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var received guest.TCPScenarioRequest
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	if string(received.Config) != c.PluginConfig {
		t.Fatalf("config changed: %s", received.Config)
	}
	for _, invalid := range []string{`null`, ` null `, `[]`, `42`, `{"x":1} {}`} {
		c.PluginConfig = invalid
		if _, err := tcpScenarioRequest(c); err == nil {
			t.Fatalf("accepted config %s", invalid)
		}
	}
	for _, valid := range []string{"", `{}`} {
		c.PluginConfig = valid
		req, err := tcpScenarioRequest(c)
		if err != nil || string(req.Config) != `{}` {
			t.Fatalf("empty object config %q: request=%+v, err=%v", valid, req, err)
		}
	}
}

func TestTCPScenarioRejectsOtherRouteDevice(t *testing.T) {
	// Loopback has a deterministic local route and requires no test topology.
	x := &Xdperf{cfg: tcpTestConfig(), Device: &net.Interface{Index: -1, Name: "scenario-test"}, Logger: zap.NewNop()}
	x.cfg.PluginName = "heavyhitter.go"
	x.cfg.TCPDst = "127.0.0.1:5201"
	_, err := x.resolveTCPTarget()
	if err == nil || !strings.Contains(err.Error(), "does not use device scenario-test") {
		t.Fatalf("route mismatch: %v", err)
	}
}
