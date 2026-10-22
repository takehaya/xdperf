package xdperf

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestMixedDrainSchedulingGrace(t *testing.T) {
	// At 2,000 iterations/s, a last active flow among 55,536 entries takes
	// longer to revisit than the old 26.4s deadline. Simulate the worst cursor
	// position, then retry a FIN only when that flow is visited again.
	for _, workers := range []uint64{1, 2, 8} {
		const flows = uint64(55536)
		repeat := uint64(20) / workers
		interval := time.Duration(repeat*workers) * time.Second / 2000
		grace := mixedDrainSchedulingGrace(flows, workers, repeat, interval)
		perWorker := (flows + workers - 1) / workers
		const rto = 200 * time.Millisecond
		deadline := tcpBackoffSpan*rto + time.Second + grace
		var now, lastSend time.Duration
		retries, cursor := -1, uint64(0)
		for retries <= tcpMaxFinRetries && now < deadline {
			now += interval
			for i := uint64(0); i < repeat; i++ {
				if cursor == perWorker-1 && (retries < 0 || now-lastSend > rto<<retries) {
					lastSend = now
					retries++
				}
				cursor = (cursor + 1) % perWorker
			}
		}
		if retries <= tcpMaxFinRetries {
			t.Fatalf("%d workers: deadline %s interrupted FIN retries (%d)", workers, deadline, retries)
		}
	}
	if grace := mixedDrainSchedulingGrace(55536, 1, tcpTxRepeatBurst, 0); grace != 0 {
		t.Fatalf("unlimited sender has scheduling delay: %s", grace)
	}
	// --pps below the worker count produces intervals above one second.
	if grace := mixedDrainSchedulingGrace(1, 8, 1, 8*time.Second); grace < 16*time.Second {
		t.Fatalf("fractional worker rate: %s", grace)
	}
}

func TestMixedRejectsOtherRouteDevice(t *testing.T) {
	// Loopback has a deterministic local route and requires no test topology.
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{Index: -1, Name: "mixed-test"}, Logger: zap.NewNop()}
	x.cfg.PluginName = "mixed.go"
	_, err := x.resolveTCPTarget("127.0.0.1:5201", 0)
	if err == nil || !strings.Contains(err.Error(), "does not use device mixed-test") {
		t.Fatalf("route mismatch: %v", err)
	}
}

func mixedResponse() *guest.GeneratorProcessResponse {
	return &guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeVariable, VariablePacketTemplate: guest.PacketVariantSet{Pattern: guest.VariantSelectionModeMixed, TCPPortBase: 40000, Variants: []guest.PacketVariant{
		{Weight: 3, Base: guest.BasePacket{Data: make([]byte, 64), Length: 64}},
		{Kind: "tcp_flow", Weight: 1, TCPFlow: &guest.TCPFlowVariant{Destination: "192.0.2.2:5201", Flows: []guest.TCPFlow{{Bytes: "65536"}, {Bytes: "65536"}, {Bytes: "65536"}, {Bytes: "67108864"}}}},
	}}}
}
func mixedConfig() Config {
	return Config{Device: "lo", Sender: true, Parallelism: 1, XDPMode: "auto", Count: 100, PluginName: "mixed.go"}
}
func TestMixedValidation(t *testing.T) {
	for name, mutate := range map[string]func(*guest.GeneratorProcessResponse){
		"unknown kind": func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[0].Kind = "typo" },
		"empty body":   func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[1].TCPFlow = nil },
		"packet union": func(r *guest.GeneratorProcessResponse) {
			r.VariablePacketTemplate.Variants[0].TCPFlow = r.VariablePacketTemplate.Variants[1].TCPFlow
		},
		"tcp union":       func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[1].Base.Length = 64 },
		"weight zero":     func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[0].Weight = 0 },
		"weight overflow": func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[0].Weight = math.MaxUint32 },
		"pattern":         func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Pattern = "sequential" },
		"empty flows":     func(r *guest.GeneratorProcessResponse) { r.VariablePacketTemplate.Variants[1].TCPFlow.Flows = nil },
		"capacity": func(r *guest.GeneratorProcessResponse) {
			r.VariablePacketTemplate.Variants[1].TCPFlow.Flows = make([]guest.TCPFlow, 65536)
		},
		"hostname": func(r *guest.GeneratorProcessResponse) {
			r.VariablePacketTemplate.Variants[1].TCPFlow.Destination = "localhost:80"
		},
		"port": func(r *guest.GeneratorProcessResponse) {
			r.VariablePacketTemplate.Variants[1].TCPFlow.Destination = "192.0.2.2:65536"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := mixedResponse()
			mutate(r)
			x := &Xdperf{cfg: mixedConfig()}
			before := x.cfg
			if err := x.prepareMixed(r); err == nil {
				t.Fatal("accepted invalid input")
			}
			if !reflect.DeepEqual(before, x.cfg) || x.mixed != nil {
				t.Fatal("partial mutation")
			}
		})
	}
	for _, value := range []string{"", "-1", "+1", " 1", "1e6", "18446744073709551616"} {
		r := mixedResponse()
		r.VariablePacketTemplate.Variants[1].TCPFlow.Flows[0].Bytes = value
		x := &Xdperf{cfg: mixedConfig()}
		if err := x.prepareMixed(r); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants[1].TCPFlow.Flows[0].Bytes = "18446744073709551615"
	x := &Xdperf{cfg: mixedConfig()}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if x.tcpVariantBytes[0] != math.MaxUint64 || x.mixed.flows != 4 || x.mixed.packetWeight != 3 || x.mixed.totalWeight != 4 {
		t.Fatalf("bad plan: %+v", x)
	}
}

func TestTCPOnlyPlan(t *testing.T) {
	for _, groups := range []int{1, 2} {
		t.Run(fmt.Sprint(groups), func(t *testing.T) {
			r := mixedResponse()
			tcp := r.VariablePacketTemplate.Variants[1]
			r.VariablePacketTemplate.Variants = []guest.PacketVariant{tcp}
			if groups == 2 {
				r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, tcp)
			}
			x := &Xdperf{cfg: mixedConfig()}
			x.cfg.Count = 0
			if err := x.prepareMixed(r); err != nil {
				t.Fatal(err)
			}
			if len(x.mixed.packets.VariablePacketTemplate.Variants) != 0 || x.mixed.packetWeight != 0 || x.mixed.totalWeight != uint32(groups) {
				t.Fatalf("unexpected packet plan: %+v", x.mixed)
			}
			if x.mixed.flows != 4*groups || len(x.tcpVariantBytes) != 4*groups || len(x.mixed.groups) != groups {
				t.Fatalf("unexpected TCP plan: %+v", x.mixed)
			}
			for i, g := range x.mixed.groups {
				if g.first != uint32(4*i) || g.count != 4 || g.weight != 1 {
					t.Fatalf("group %d: %+v", i, g)
				}
			}
		})
	}
}

func TestMixedUnlimitedRunBounds(t *testing.T) {
	for _, bounds := range []struct {
		count    uint64
		duration time.Duration
		wantErr  bool
	}{{0, 0, true}, {100, 0, false}, {0, time.Second, false}} {
		r := mixedResponse()
		r.VariablePacketTemplate.Variants[1].TCPFlow.Flows[0].Bytes = "0"
		x := &Xdperf{cfg: mixedConfig()}
		x.cfg.Count, x.cfg.Duration = bounds.count, bounds.duration
		if err := x.prepareMixed(r); (err != nil) != bounds.wantErr {
			t.Fatalf("bounds %+v: %v", bounds, err)
		}
	}
}

func TestMixedCountReached(t *testing.T) {
	x := &Xdperf{cfg: Config{Count: 5}, mixed: &mixedPlan{}, cpus: []int{2, 0}}
	states := []coreelf.BpfPktState{{Budget: 0}, {Budget: math.MaxUint64}, {Budget: 1}}
	if x.mixedCountReached(0, states) {
		t.Fatal("stopped with an unspent worker budget")
	}
	states[2].Budget = 0
	if x.mixedCountReached(1, states) {
		t.Fatal("stopped with shared budget remaining")
	}
	if !x.mixedCountReached(0, states) {
		t.Fatal("did not stop after all selected workers exhausted their budgets")
	}
	x.cfg.Count = 0
	if x.mixedCountReached(0, states) {
		t.Fatal("unbounded run stopped")
	}
	x.cfg.Count, x.mixed = 5, nil
	if x.mixedCountReached(0, states) {
		t.Fatal("packet mode stopped")
	}
}

func TestMixedWorkerWarning(t *testing.T) {
	for _, tt := range []struct {
		packets                  uint32
		flows, workers, warnings int
	}{
		{0, 1, 2, 1}, {0, 2, 2, 0}, {1, 1, 2, 0},
	} {
		core, logs := observer.New(zap.WarnLevel)
		x := &Xdperf{mixed: &mixedPlan{flows: tt.flows, packetWeight: tt.packets}, cpus: make([]int, tt.workers), Logger: zap.New(core)}
		x.warnMixedWorkers()
		if logs.Len() != tt.warnings {
			t.Fatalf("%+v: got %d warnings", tt, logs.Len())
		}
	}
}

func TestMixedCountRange(t *testing.T) {
	x := &Xdperf{cfg: mixedConfig()}
	x.cfg.Count = math.MaxInt64 + 1
	if err := x.prepareMixed(mixedResponse()); err == nil || !strings.Contains(err.Error(), "mixed --count must be <=") {
		t.Fatalf("expected signed count range error, got %v", err)
	}
}

func TestMixedTCPKnobs(t *testing.T) {
	for name, mutate := range map[string]func(*guest.TCPFlowVariant){
		"window overflow": func(f *guest.TCPFlowVariant) { f.WindowSegs = 65536 },
		"small MSS":       func(f *guest.TCPFlowVariant) { f.MSS = 63 },
		"invalid IP ID":   func(f *guest.TCPFlowVariant) { f.IPID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			r := mixedResponse()
			mutate(r.VariablePacketTemplate.Variants[1].TCPFlow)
			x := &Xdperf{cfg: mixedConfig()}
			if err := x.prepareMixed(r); err == nil || x.mixed != nil {
				t.Fatalf("accepted invalid knobs: %v", err)
			}
		})
	}
	for _, portBase := range []uint16{0, 12001, 65532, 65533} {
		t.Run(fmt.Sprint(portBase), func(t *testing.T) {
			r := mixedResponse()
			r.VariablePacketTemplate.TCPPortBase = portBase
			f := r.VariablePacketTemplate.Variants[1].TCPFlow
			f.WindowSegs, f.MSS, f.RTOMillis, f.IPID = 65535, 64, math.MaxUint32, "flow"
			x := &Xdperf{cfg: mixedConfig(), Logger: zap.NewNop(), cpus: []int{0}}
			err := x.prepareMixed(r)
			if portBase == 65533 {
				if err == nil || x.mixed != nil {
					t.Fatal("accepted overflowing port range")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			g := x.mixed.groups[0]
			if g.window != 65535 || g.mss != 64 || g.rto != time.Duration(math.MaxUint32)*time.Millisecond || g.ipIDShared != 0 {
				t.Fatalf("plugin overrides lost: %+v", g)
			}
			want := int(portBase)
			if want == 0 {
				want = 10000
			}
			if x.mixed.portBase != want {
				t.Fatalf("port base = %d, want %d", x.mixed.portBase, want)
			}
		})
	}
	r := mixedResponse()
	f := r.VariablePacketTemplate.Variants[1].TCPFlow
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, guest.PacketVariant{Kind: "tcp_flow", Weight: 1,
		TCPFlow: &guest.TCPFlowVariant{Destination: f.Destination, WindowSegs: 3, MSS: 512, RTOMillis: 50, IPID: "flow", Flows: f.Flows}})
	x := &Xdperf{cfg: mixedConfig(), Logger: zap.NewNop(), cpus: []int{0}}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	g := x.mixed.groups[0]
	if g.window != 32 || g.mss != 0 || g.rto != 200*time.Millisecond || g.ipIDShared != 0 || x.tcpRTO() != g.rto {
		t.Fatalf("default settings lost: %+v", g)
	}
	x.mixed.groups[0].rto = 25 * time.Millisecond
	if x.tcpRTO() != 50*time.Millisecond {
		t.Fatal("shutdown uses default RTO instead of maximum group RTO")
	}
}

func TestTCPConnectionsValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		connections *uint32
		duration    time.Duration
		count       uint64
		bytes       string
		variants    int
		want        int
	}{
		{"omitted", nil, 0, 0, "1024", 1, 4},
		{"finite", ptrConnections(1000), 0, 0, "1024", 1, 1000},
		{"partial batch", ptrConnections(7), 0, 0, "1024", 1, 7},
		{"fewer than slots", ptrConnections(2), 0, 0, "1024", 1, 2},
		{"duration", ptrConnections(0), time.Second, 0, "1024", 1, 25536},
		{"capacity", ptrConnections(25536), 0, 0, "1024", 1, 25536},
		{"over capacity", ptrConnections(25537), 0, 0, "1024", 1, 0},
		{"overflow", ptrConnections(math.MaxUint32), 0, 0, "1024", 1, 0},
		{"zero without duration", ptrConnections(0), 0, 0, "1024", 1, 0},
		{"unlimited bytes", ptrConnections(10), time.Second, 0, "0", 1, 0},
		{"count", ptrConnections(10), 0, 5, "1024", 1, 0},
		{"multiple TCP variants", ptrConnections(10), 0, 0, "1024", 2, 0},
		{"packet mixture", ptrConnections(10), 0, 0, "1024", 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := mixedResponse()
			v := resp.VariablePacketTemplate.Variants[1]
			v.TCPFlow.Connections = tc.connections
			for i := range v.TCPFlow.Flows {
				v.TCPFlow.Flows[i].Bytes = tc.bytes
			}
			resp.VariablePacketTemplate.Variants = []guest.PacketVariant{v}
			if tc.variants == 2 {
				resp.VariablePacketTemplate.Variants = append(resp.VariablePacketTemplate.Variants, v)
			}
			if tc.variants == 3 {
				resp.VariablePacketTemplate.Variants = append(resp.VariablePacketTemplate.Variants, guest.PacketVariant{Weight: 1})
			}
			cfg := mixedConfig()
			cfg.Count, cfg.Duration = tc.count, tc.duration
			x := &Xdperf{cfg: cfg, Logger: zap.NewNop()}
			err := x.prepareMixed(resp)
			if tc.want == 0 {
				if err == nil {
					t.Fatal("accepted invalid connections")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if x.mixed.flows != 4 || x.mixed.connections != tc.want || x.mixed.repeat != (tc.connections != nil) {
				t.Fatalf("plan: %+v", x.mixed)
			}
		})
	}
}

func ptrConnections(n uint32) *uint32 { return &n }

func TestTCPConnectionsUnusedSlotsNeedNoPorts(t *testing.T) {
	resp := mixedResponse()
	resp.VariablePacketTemplate.Variants = resp.VariablePacketTemplate.Variants[1:]
	resp.VariablePacketTemplate.TCPPortBase = 65534
	resp.VariablePacketTemplate.Variants[0].TCPFlow.Connections = ptrConnections(2)
	cfg := mixedConfig()
	cfg.Count = 0
	x := &Xdperf{cfg: cfg, Logger: zap.NewNop()}
	if err := x.prepareMixed(resp); err != nil {
		t.Fatal(err)
	}
	if x.mixed.flows != 4 || x.mixed.connections != 2 {
		t.Fatalf("plan: %+v", x.mixed)
	}
}

func TestTCPConnectionsIgnoresDerivedPacketCount(t *testing.T) {
	for _, connections := range []uint32{0, 1000} {
		resp := mixedResponse()
		resp.VariablePacketTemplate.Variants = resp.VariablePacketTemplate.Variants[1:]
		resp.VariablePacketTemplate.Variants[0].TCPFlow.Connections = ptrConnections(connections)
		cfg := mixedConfig()
		cfg.Count = 10000
		cfg.CountFromDuration = true
		cfg.Duration = 10 * time.Second
		cfg.PPS = 1000
		x := &Xdperf{cfg: cfg, Logger: zap.NewNop()}
		if err := x.prepareMixed(resp); err != nil {
			t.Fatal(err)
		}
		if x.cfg.Count != 0 || x.cfg.PPS != 1000 || x.cfg.Duration != 10*time.Second {
			t.Fatalf("config: %+v", x.cfg)
		}
	}
}

func TestTCPConnectionsIgnoresDerivedBudgetErrors(t *testing.T) {
	for _, count := range []uint64{0, 1, math.MaxUint64} {
		resp := mixedResponse()
		resp.VariablePacketTemplate.Variants = resp.VariablePacketTemplate.Variants[1:]
		resp.VariablePacketTemplate.Variants[0].TCPFlow.Connections = ptrConnections(0)
		budgetErr := fmt.Errorf("invalid derived packet budget")
		cfg := mixedConfig()
		cfg.Count = count
		cfg.CountFromDuration = true
		cfg.DurationCountError = budgetErr
		cfg.Duration = time.Second
		cfg.PPS = 1
		cfg.Parallelism = 4
		if err := cfg.validateRunBounds(nil); err != budgetErr {
			t.Fatalf("packet budget error was ignored: %v", err)
		}
		if err := cfg.validateRunBounds(&mixedPlan{}); err != budgetErr {
			t.Fatalf("legacy TCP budget error was ignored: %v", err)
		}
		x := &Xdperf{cfg: cfg, Logger: zap.NewNop()}
		if err := x.prepareMixed(resp); err != nil {
			t.Fatal(err)
		}
		if err := x.cfg.validateRunBounds(x.mixed); err != nil {
			t.Fatal(err)
		}
		if x.cfg.Count != 0 {
			t.Fatal("derived packet budget was retained")
		}
	}
}
