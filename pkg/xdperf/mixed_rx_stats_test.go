package xdperf

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestMixedRXDiagnostics(t *testing.T) {
	for _, extended := range []bool{false, true} {
		t.Run(fmt.Sprintf("extended=%v", extended), func(t *testing.T) { testMixedRXDiagnostics(t, extended) })
	}
}
func testMixedRXDiagnostics(t *testing.T, extended bool) {
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants[1].Base = tcpTestBase(false, 0)
	r.VariablePacketTemplate.Variants[1].TCPFlow.Timestamps = extended
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	objs := loadMixedTestObjects(t, x.mixed.features)
	x.bpfobjs = objs
	target, err := parseTCPVariant(x.mixed.groups[0].variant)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.initTCPMaps(target, x.mixed.groups[0].variant.Base.Data); err != nil {
		t.Fatal(err)
	}
	// Test both direct and tail-called RX. UDP fallback must retain its accounting.
	if err := objs.MixedCfgMap.Put(uint32(0), coreelf.BpfMixedCfg{Receive: 1}); err != nil {
		t.Fatal(err)
	}
	var tmpl coreelf.BpfTcpTemplate
	if err := objs.TcpTemplateMap.Lookup(uint32(0), &tmpl); err != nil {
		t.Fatal(err)
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, tmpl.Cfg.DstPort)
	binary.BigEndian.PutUint16(tcp[2:], 40000)
	tcp[12] = 0x50
	ip := rxIP(false, 6, tcp)
	copy(ip[12:16], targetIP(tmpl.Cfg.DstIp)[:4])
	copy(ip[16:20], targetIP(tmpl.Cfg.SrcIp)[:4])
	change := func(off int, value byte) []byte {
		b := append([]byte(nil), ip...)
		b[off] = value
		return rxTunnel("bare", b)
	}
	udp := []byte{0, 1, 0, 53, 0, 8, 0, 0}
	// Use a full ND-sized body; the diagnostic classification is not ND validation.
	nd := rxIP(true, 58, append([]byte{135}, make([]byte, 23)...))
	arp := rxEther(0x806, make([]byte, 28))
	vxarp := rxTunnel("vxlan", ip)
	vxarp = append(vxarp[:50], arp...)
	binary.BigEndian.PutUint16(vxarp[16:], uint16(len(vxarp)-14))
	binary.BigEndian.PutUint16(vxarp[38:], uint16(len(vxarp)-34))
	ip6 := rxIP(true, 6, tcp)
	malformedTuple := func(length byte, doff byte) []byte {
		b := append([]byte(nil), ip...)
		b[3] = length
		b[12] = 203
		b[32] = doff
		return rxTunnel("bare", b)
	}
	cases := []struct {
		name   string
		frame  []byte
		reason int
		action uint32
	}{
		{"matched", rxTunnel("bare", ip), -1, 1},
		{"matched_tunnel", rxTunnel("gre-key", ip), -1, 1},
		{"port_below", change(22, 0), 1, 2},
		{"port_above", change(22, 0xff), 1, 2},
		{"source_port", change(20, 0), 2, 2},
		{"source_ip", change(12, 203), 2, 2},
		{"destination_ip", change(16, 203), 2, 2},
		{"version", rxTunnel("bare", ip6), 2, 2},
		{"tunnel_tuple", rxTunnel("ipip4", append(append([]byte(nil), ip[:12]...), append([]byte{203}, ip[13:]...)...)), 2, 2},
		{"tcp_doff_short", change(32, 0x40), 5, 1},
		{"tcp_doff_long", change(32, 0xf0), 5, 1},
		{"ip_length_short", change(3, 39), 5, 1},
		{"ip_length_long", change(3, 80), 5, 1},
		{"unmatched_ip_short", malformedTuple(20, 0x50), 0, 2},
		{"unmatched_ip_long", malformedTuple(80, 0x50), 0, 2},
		{"unmatched_tcp_short", malformedTuple(40, 0x40), 0, 2},
		{"unmatched_tcp_long", malformedTuple(40, 0xf0), 0, 2},
		{"unmatched_tunnel_ip_short", rxTunnel("gre-key", malformedTuple(20, 0x50)[14:]), 0, 2},
		{"ipv4_options", change(0, 0x46), 0, 2},
		{"fragment", change(6, 0x20), 0, 2},
		{"unsupported_tunnel", rxEther(0x800, rxIP(false, 50, make([]byte, 20))), 0, 2},
		{"depth_limit", rxTunnel("five-layers", ip), 0, 2},
		{"offset_limit", rxTunnel("geneve-240", ip), 0, 1},
		{"truncated", rxTunnel("bare", ip)[:45], 0, 2},
		{"arp", arp, 3, 2},
		{"tunnel_arp", vxarp, 3, 2},
		{"nd", rxTunnel("bare", nd), 3, 2},
		{"tunnel_nd", rxTunnel("ipip6", nd), 3, 2},
		{"udp", rxEther(0x800, rxIP(false, 17, udp)), 4, 1},
		{"mpls_udp", rxTunnel("mpls-one", rxIP(false, 17, udp)), 4, 2},
		{"mpls_icmp", rxTunnel("mpls-one", rxIP(false, 1, make([]byte, 8))), 4, 2},
		{"gre_mpls_udp", rxTunnel("gre-mpls", rxIP(false, 17, udp)), 4, 2},
		{"gre_mpls_icmp", rxTunnel("gre-mpls", rxIP(false, 1, make([]byte, 8))), 4, 2},
		{"mpls_nd", rxTunnel("mpls-one", nd), 3, 2},
		{"tunnel_udp", rxTunnel("gre-key", rxIP(false, 17, udp)), 4, 2},
		{"icmp", rxEther(0x800, rxIP(false, 1, make([]byte, 8))), 4, 2},
	}
	if extended {
		for _, opts := range [][]byte{{8, 2, 0, 0}, append(timestampOption(1), timestampOption(2)...)} {
			b := append([]byte(nil), ip...)
			b = append(b, opts...)
			b[3] = byte(len(b))
			b[32] = byte((20+len(opts))/4) << 4
			cases = append(cases, struct {
				name   string
				frame  []byte
				reason int
				action uint32
			}{fmt.Sprintf("invalid_timestamp_%d", len(opts)), rxTunnel("bare", b), 5, 1})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, prog := range []*ebpf.Program{objs.XdpRxTcpMixed, objs.XdpRxMixed} {
				before, err := x.readMixedRXStats()
				if err != nil {
					t.Fatal(err)
				}
				action, _, err := prog.Test(tc.frame)
				if err != nil {
					t.Fatal(err)
				}
				if action != tc.action {
					t.Fatalf("action=%d want=%d", action, tc.action)
				}
				after, err := x.readMixedRXStats()
				if err != nil {
					t.Fatal(err)
				}
				for i := range after {
					want := uint64(0)
					if i == tc.reason {
						want = 1
					}
					if after[i]-before[i] != want {
						t.Errorf("%s delta=%d want=%d", mixedRXReasons[i], after[i]-before[i], want)
					}
				}
			}
		})
	}
	totals, err := x.readMixedRXStats()
	if err != nil {
		t.Fatal(err)
	}
	observed, logs := observer.New(zap.InfoLevel)
	x.Logger = zap.New(observed)
	if err := x.showMixedStats(); err != nil {
		t.Fatal(err)
	}
	warnings := logs.FilterLevelExact(zap.WarnLevel).All()
	if len(warnings) != 1 || warnings[0].ContextMap()["rx_tuple_mismatch"] != totals[2] {
		t.Fatalf("tuple warning: %+v", warnings)
	}
	final := logs.FilterMessage("mixed final statistics").All()
	if len(final) != 1 {
		t.Fatalf("missing final stats: %+v", final)
	}
	for i, reason := range mixedRXReasons {
		if final[0].ContextMap()["rx_"+reason] != totals[i] {
			t.Errorf("final %s != %d", reason, totals[i])
		}
	}

}
