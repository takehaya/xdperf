package xdperf

import (
	"math"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
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
	for _, value := range []string{"", "0", "-1", "+1", " 1", "1e6", "18446744073709551616"} {
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
