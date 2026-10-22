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
	x := &Xdperf{cfg: tcpTestConfig(), Device: &net.Interface{Index: -1, Name: "mixed-test"}, Logger: zap.NewNop()}
	x.cfg.PluginName = "mixed.go"
	x.cfg.TCPDst = "127.0.0.1:5201"
	_, err := x.resolveTCPTarget()
	if err == nil || !strings.Contains(err.Error(), "does not use device mixed-test") {
		t.Fatalf("route mismatch: %v", err)
	}
}

func mixedResponse() *guest.GeneratorProcessResponse {
	return &guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeVariable, VariablePacketTemplate: guest.PacketVariantSet{Pattern: guest.VariantSelectionModeMixed, Variants: []guest.PacketVariant{
		{Weight: 3, Base: guest.BasePacket{Data: make([]byte, 64), Length: 64}},
		{Kind: "tcp_flow", Weight: 1, TCPFlow: &guest.TCPFlowVariant{Destination: "192.0.2.2:5201", Flows: []guest.TCPFlow{{Bytes: "65536"}, {Bytes: "65536"}, {Bytes: "65536"}, {Bytes: "67108864"}}}},
	}}}
}
func mixedConfig() Config {
	c := tcpTestConfig()
	c.TCP = false
	c.TCPDst = ""
	c.TCPBytes = 0
	c.TCPFlows = 1
	c.Count = 100
	c.PluginName = "mixed.go"
	return c
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
	if x.tcpVariantBytes[0] != math.MaxUint64 || x.cfg.TCPFlows != 4 || x.mixed.packetWeight != 3 || x.mixed.totalWeight != 4 {
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
			if x.cfg.TCPFlows != 4*groups || len(x.tcpVariantBytes) != 4*groups || len(x.mixed.groups) != groups {
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
		t.Fatal("standalone TCP stopped")
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
		x := &Xdperf{cfg: Config{TCPFlows: tt.flows}, mixed: &mixedPlan{packetWeight: tt.packets}, cpus: make([]int, tt.workers), Logger: zap.New(core)}
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
			x.cfg.TCPWindow, x.cfg.TCPMSS, x.cfg.TCPRTO, x.cfg.TCPIPID = 9, 1000, time.Second, "shared"
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
				want = 40000
			}
			if x.cfg.TCPPortBase != want {
				t.Fatalf("port base = %d, want %d", x.cfg.TCPPortBase, want)
			}
		})
	}
	r := mixedResponse()
	f := r.VariablePacketTemplate.Variants[1].TCPFlow
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, guest.PacketVariant{Kind: "tcp_flow", Weight: 1,
		TCPFlow: &guest.TCPFlowVariant{Destination: f.Destination, WindowSegs: 3, MSS: 512, RTOMillis: 50, IPID: "flow", Flows: f.Flows}})
	x := &Xdperf{cfg: mixedConfig(), Logger: zap.NewNop(), cpus: []int{0}}
	x.cfg.TCPWindow, x.cfg.TCPMSS, x.cfg.TCPRTO, x.cfg.TCPIPID = 11, 1200, 450*time.Millisecond, "shared"
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	g := x.mixed.groups[0]
	if g.window != 11 || g.mss != 1200 || g.rto != 450*time.Millisecond || g.ipIDShared != 1 || x.tcpRTO() != g.rto {
		t.Fatalf("CLI fallback lost: %+v", g)
	}
	x.mixed.groups[0].rto = 25 * time.Millisecond
	if x.tcpRTO() != 50*time.Millisecond {
		t.Fatal("shutdown uses CLI RTO instead of maximum group RTO")
	}
	x.mixed = nil
	if x.tcpRTO() != x.cfg.TCPRTO {
		t.Fatal("standalone RTO changed")
	}
}
