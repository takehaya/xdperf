package xdperf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// Build receive envelopes independently of the TX fixup table. In particular,
// these envelopes are never used to select the program's TX features.
func rxIP(v6 bool, next byte, payload []byte) []byte {
	n := 20
	if v6 {
		n = 40
	}
	b := append([]byte(nil), tcpTestBase(v6, 0).Data[14:14+n]...)
	if v6 {
		b[6] = next
		binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	} else {
		b[9] = next
		binary.BigEndian.PutUint16(b[2:], uint16(n+len(payload)))
	}
	return append(b, payload...)
}

func rxEther(proto uint16, payload []byte) []byte {
	b := append([]byte(nil), tcpTestBase(false, 0).Data[:14]...)
	binary.BigEndian.PutUint16(b[12:], proto)
	return append(b, payload...)
}

func rxTunnel(name string, inner []byte) []byte {
	proto, next := uint16(0x800), byte(4)
	if inner[0]>>4 == 6 {
		proto, next = 0x86dd, 41
	}
	switch name {
	case "four-layers", "five-layers":
		count := 4
		if name == "five-layers" {
			count = 5
		}
		for i := 0; i < count; i++ {
			inner = rxIP(false, next, inner)
			next = 4
		}
		return rxEther(0x800, inner)
	case "geneve-236", "geneve-240":
		l4 := 236
		if name == "geneve-240" {
			l4 = 240
		}
		iplen := 20
		if inner[0]>>4 == 6 {
			iplen = 40
		}
		opts := make([]byte, l4-64-iplen)
		for i := 0; i < len(opts); i += 4 {
			opts[i+2] = 1
		}
		h := append([]byte{byte(len(opts) / 4), 0, 0x65, 0x58, 0, 0, 7, 0}, opts...)
		h = append(h, rxEther(proto, inner)...)
		u := []byte{0x12, 0x34, 0x17, 0xc1, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(u[4:], uint16(8+len(h)))
		return rxEther(0x800, rxIP(false, 17, append(u, h...)))
	case "bare":
		return rxEther(proto, inner)
	case "ipip4":
		return rxEther(0x800, rxIP(false, next, inner))
	case "ipip6":
		return rxEther(0x86dd, rxIP(true, next, inner))
	case "srv6-one", "srv6-three", "srv6-ether":
		count := 1
		if name == "srv6-three" {
			count = 3
		}
		if name == "srv6-ether" {
			next, inner = 143, rxEther(proto, inner)
		}
		h := make([]byte, 8+16*count)
		h[0], h[1], h[2], h[3], h[4] = next, byte(count*2), 4, byte(count-1), byte(count-1)
		return rxEther(0x86dd, rxIP(true, 43, append(h, inner...)))
	case "gre", "gre-key", "gretap", "ip6gre", "gre-mpls":
		outer6 := name == "ip6gre"
		if name == "gretap" {
			proto, inner = 0x6558, rxEther(proto, inner)
		}
		if name == "gre-mpls" {
			proto, inner = 0x8847, append([]byte{0, 1, 1, 64}, inner...)
		}
		h := []byte{0, 0, byte(proto >> 8), byte(proto)}
		if name == "gre-key" {
			h[0] = 0x20
			h = append(h, 0xde, 0xad, 0xbe, 0xef)
		}
		outerProto := uint16(0x800)
		if outer6 {
			outerProto = 0x86dd
		}
		return rxEther(outerProto, rxIP(outer6, 47, append(h, inner...)))
	case "mpls-one", "mpls-eight", "mpls-nine":
		count := 1
		if name == "mpls-eight" {
			count = 8
		}
		if name == "mpls-nine" {
			count = 9
		}
		h := make([]byte, count*4)
		for i := 0; i < count; i++ {
			h[i*4+1], h[i*4+3] = byte(i+1), 64
		}
		h[len(h)-2] = 1
		return rxEther(0x8847, append(h, inner...))
	case "gtpu", "gtpu-spare", "gtpu-spn-unusedext", "gtpu-spn", "gtpu-ext", "gtpu-eight", "gtpu-nine":
		h := []byte{0x30, 0xff, 0, 0, 0xde, 0xad, 0xbe, 0xef}
		if name == "gtpu-spare" {
			h[0] |= 8
		}
		if name == "gtpu-spn" || name == "gtpu-spn-unusedext" {
			h[0] |= 3
			h = append(h, 0xff, 0xff, 9, 0)
			if name == "gtpu-spn-unusedext" {
				h[11] = 0x85
			}
		}
		if name == "gtpu-ext" || name == "gtpu-eight" || name == "gtpu-nine" {
			count := 1
			if name == "gtpu-eight" {
				count = 8
			}
			if name == "gtpu-nine" {
				count = 9
			}
			h[0] |= 4
			h = append(h, 0, 0, 0, 0x85)
			for i := 0; i < count; i++ {
				ext := byte(0x85)
				if i == count-1 {
					ext = 0
				}
				h = append(h, 1, 0x10, 0, ext)
			}
		}
		binary.BigEndian.PutUint16(h[2:], uint16(len(h)-8+len(inner)))
		u := []byte{0x12, 0x34, 8, 0x68, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(u[4:], uint16(8+len(h)+len(inner)))
		return rxEther(0x800, rxIP(false, 17, append(append(u, h...), inner...)))
	case "nested":
		// IPv6/SRH/IPv4/GRE/MPLS/IPv4-or-IPv6/TCP.
		return rxTunnel("srv6-three", rxTunnel("gre-mpls", inner)[14:])
	default:
		panic(name)
	}
}

func TestTCPReceiveTunnels(t *testing.T) {
	objs, spec, err := coreelf.ReadBaseCollectionWithSizes(map[string]any{"swap_resp": uint32(0)}, map[string]uint32{"diff_map": 100})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfobjs: objs, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[:1]
	for _, v6 := range []bool{false, true} {
		r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: tcpTestBase(v6, 0), TCPFlow: &guest.TCPFlowVariant{Flows: []guest.TCPFlow{{Bytes: "3"}}}})
	}
	if err = x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if err = coreelf.LoadMixedProgramsWithFeatures(objs, spec, x.mixed.features); err != nil {
		t.Fatal(err)
	}
	target, err := parseTCPVariant(x.mixed.groups[0].variant)
	if err != nil {
		t.Fatal(err)
	}
	target.mss = 1024
	if err = x.initTCPMaps(target, x.mixed.groups[0].variant.Base.Data); err != nil {
		t.Fatal(err)
	}
	for idx, v6 := range []bool{false, true} {
		var tmpl coreelf.BpfTcpTemplate
		if err = objs.TcpTemplateMap.Lookup(uint32(idx), &tmpl); err != nil {
			t.Fatal(err)
		}
		l4 := 20
		if v6 {
			l4 = 40
		}
		reply := func(flags byte, seq, ack uint32) []byte {
			b := append([]byte(nil), tcpTestBase(v6, 0).Data[14:]...)
			if v6 {
				copy(b[8:24], targetIP(tmpl.Cfg.DstIp))
				copy(b[24:40], targetIP(tmpl.Cfg.SrcIp))
				binary.BigEndian.PutUint16(b[4:], 20)
			} else {
				copy(b[12:16], targetIP(tmpl.Cfg.DstIp)[:4])
				copy(b[16:20], targetIP(tmpl.Cfg.SrcIp)[:4])
				binary.BigEndian.PutUint16(b[2:], 40)
			}
			binary.BigEndian.PutUint16(b[l4:], tmpl.Cfg.DstPort)
			binary.BigEndian.PutUint16(b[l4+2:], uint16(40000+idx))
			binary.BigEndian.PutUint32(b[l4+4:], seq)
			binary.BigEndian.PutUint32(b[l4+8:], ack)
			b[l4+12], b[l4+13] = 0x50, flags
			binary.BigEndian.PutUint16(b[l4+14:], 65535)
			return b
		}
		initial := coreelf.BpfTcpFlow{TemplateId: uint32(idx), State: tcpFlowSynSent, SrcPort: uint16(40000 + idx), Iss: 100, SndUna: 100, SndNxt: 101, SndMax: 101, Mss: tmpl.Cfg.Mss, BytesTarget: 3}
		put := func(f coreelf.BpfTcpFlow) {
			t.Helper()
			if e := objs.TcpFlowMap.Put(uint32(idx), f); e != nil {
				t.Fatal(e)
			}
		}
		get := func() coreelf.BpfTcpFlow {
			t.Helper()
			var f coreelf.BpfTcpFlow
			if e := objs.TcpFlowMap.Lookup(uint32(idx), &f); e != nil {
				t.Fatal(e)
			}
			return f
		}
		for _, name := range []string{"bare", "ipip4", "ipip6", "srv6-one", "srv6-three", "srv6-ether", "gre", "gre-key", "gretap", "ip6gre", "gre-mpls", "mpls-one", "mpls-eight", "gtpu", "gtpu-spare", "gtpu-spn-unusedext", "gtpu-spn", "gtpu-ext", "gtpu-eight", "nested", "four-layers", "geneve-236"} {
			t.Run(fmt.Sprintf("v6=%v/%s", v6, name), func(t *testing.T) {
				put(initial)
				rx := func(b []byte, want uint32) {
					t.Helper()
					a, out, e := objs.XdpRxMixed.Test(rxTunnel(name, b))
					if e != nil || a != want {
						t.Fatalf("RX action %d, want %d: %v", a, want, e)
					}
					if a == 3 {
						verifyTCPEncapFrame(t, out, tmpl)
					}
				}
				rx(reply(0x12, 5000, 101), 3)
				f := get()
				if f.State != tcpFlowEstablished {
					t.Fatalf("SYN: %+v", f)
				}
				states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
				for i := range states {
					states[i].SelectedFlow = uint32(idx)
				}
				if e := objs.MixedStateMap.Put(uint32(0), states); e != nil {
					t.Fatal(e)
				}
				tx := func() {
					t.Helper()
					a, out, e := objs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
					if e != nil || a != 3 {
						t.Fatalf("TX %d %v", a, e)
					}
					verifyTCPEncapFrame(t, out, tmpl)
				}
				tx()
				rx(reply(0x10, 5001, 104), 1)
				if f = get(); f.BytesAcked != 3 {
					t.Fatalf("ACK: %+v", f)
				}
				tx()
				rx(reply(0x11, 5001, 105), 3)
				if f = get(); f.State != tcpFlowDone || f.BytesAcked != 3 {
					t.Fatalf("FIN: %+v", f)
				}
				// Every truncated envelope must leave the flow untouched.
				frame := rxTunnel(name, reply(0x12, 5000, 101))
				for n := 14; n < len(frame); n++ {
					put(initial)
					_, _, e := objs.XdpRxMixed.Test(frame[:n])
					if e != nil {
						t.Fatal(e)
					}
					if f = get(); f != initial {
						t.Fatalf("truncation %d changed flow: %+v", n, f)
					}
				}
			})
		}
		invalid := map[string][]byte{}
		for _, name := range []string{"mpls-nine", "gtpu-nine", "five-layers", "geneve-240"} {
			invalid[name] = rxTunnel(name, reply(0x12, 5000, 101))
		}
		bad := func(name, kind string, mutate func([]byte)) {
			b := rxTunnel(kind, reply(0x12, 5000, 101))
			mutate(b)
			invalid[name] = b
		}
		bad("SRH type", "srv6-one", func(b []byte) { b[56] = 3 })
		bad("SRH short list", "srv6-three", func(b []byte) { b[55] = 2 })
		bad("SRH segments left", "srv6-one", func(b []byte) { b[57] = 2 })
		bad("SRH parent length", "srv6-one", func(b []byte) { binary.BigEndian.PutUint16(b[18:], 24) })
		bad("GRE sequence", "gre", func(b []byte) { b[34] = 0x10 })
		bad("GRE version", "gre", func(b []byte) { b[35] = 1 })
		bad("GRE short key", "gre-key", func(b []byte) { binary.BigEndian.PutUint16(b[16:], 24) })
		bad("GTP short length", "gtpu", func(b []byte) { binary.BigEndian.PutUint16(b[44:], 1) })
		bad("GTP long length", "gtpu", func(b []byte) { binary.BigEndian.PutUint16(b[44:], 65535) })
		bad("GTP message", "gtpu", func(b []byte) { b[43] = 1 })
		bad("GTP zero extension", "gtpu-ext", func(b []byte) { b[54] = 0 })
		bad("GTP long extension", "gtpu-ext", func(b []byte) { b[54] = 255 })
		bad("GTP missing E", "gtpu-ext", func(b []byte) { b[42] = 0x32 })
		bad("MPLS missing bottom", "mpls-one", func(b []byte) { b[16] = 0 })
		bad("MPLS unknown version", "mpls-one", func(b []byte) { b[18] = 0x70 })
		bad("outer fragment", "ipip4", func(b []byte) { b[20] = 0x20 })
		for name, b := range invalid {
			t.Run(fmt.Sprintf("v6=%v/invalid/%s", v6, name), func(t *testing.T) {
				put(initial)
				a, _, e := objs.XdpRxMixed.Test(b)
				if e != nil || a != 2 {
					t.Fatalf("action %d: %v", a, e)
				}
				if f := get(); f != initial {
					t.Fatalf("changed flow: %+v", f)
				}
			})
		}
	}
}

func targetIP(words [4]uint32) []byte {
	b := make([]byte, 16)
	for i, w := range words {
		binary.NativeEndian.PutUint32(b[i*4:], w)
	}
	return b
}
