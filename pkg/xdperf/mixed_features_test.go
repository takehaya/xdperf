package xdperf

import (
	"testing"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

func TestMixedProgramFeatures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		variants []guest.PacketVariant
		want     coreelf.MixedProgramFeatures
	}{
		{"destination", mixedResponse().VariablePacketTemplate.Variants[1:], coreelf.MixedProgramFeatures{}},
		{"bare", []guest.PacketVariant{{Kind: "tcp_flow", Weight: 1, Base: tcpTestBase(true, 2), TCPFlow: &guest.TCPFlowVariant{Flows: []guest.TCPFlow{{Bytes: "100"}}}}}, coreelf.MixedProgramFeatures{}},
		{"vxlan-zero", []guest.PacketVariant{tcpTestTunnel("vxlan", false, false, "zero")}, coreelf.MixedProgramFeatures{Lengths: 2, OuterIPs: 1, UDPs: 1}},
		{"vxlan-lco", []guest.PacketVariant{tcpTestTunnel("vxlan", false, false, "lco")}, coreelf.MixedProgramFeatures{Lengths: 2, OuterIPs: 1, UDPs: 1, LCO: true}},
		{"geneve-v6", []guest.PacketVariant{tcpTestTunnel("geneve", true, true, "lco")}, coreelf.MixedProgramFeatures{Lengths: 2, OuterIPs: 1, UDPs: 1, LCO: true}},
		{"nested", []guest.PacketVariant{tcpOtherTunnel("nested")}, coreelf.MixedProgramFeatures{Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true}},
		{"union", []guest.PacketVariant{tcpOtherTunnel("nested"), tcpTestTunnel("vxlan", false, false, "zero")}, coreelf.MixedProgramFeatures{Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &Xdperf{cfg: mixedConfig()}
			r := mixedResponse()
			r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], tc.variants...)
			if err := x.prepareMixed(r); err != nil {
				t.Fatal(err)
			}
			if x.mixed.features != tc.want {
				t.Fatalf("features %+v, want %+v", x.mixed.features, tc.want)
			}
		})
	}
}
