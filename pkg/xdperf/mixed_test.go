package xdperf

import (
	"math"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

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
