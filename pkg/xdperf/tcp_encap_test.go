package xdperf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

func tcpTestTunnel(name string, outer6, inner6 bool, mode string) guest.PacketVariant {
	inner := tcpTestBase(inner6, 0).Data
	iplen := 20
	if outer6 {
		iplen = 40
	}
	outer := tcpTestBase(outer6, 0).Data[:14+iplen]
	outer = append([]byte(nil), outer...)
	udp := len(outer)
	if outer6 {
		outer[20] = 17
	} else {
		outer[23] = 17
	}
	port := uint16(4789)
	if name == "geneve" {
		port = 6081
	}
	outer = append(outer, 0, 0, byte(port>>8), byte(port), 0, 0, 0, 0)
	if name == "geneve" {
		outer = append(outer, 1, 0, 0x65, 0x58, 0, 0, 7, 0, 0x12, 0x34, 1, 0)
	} else {
		outer = append(outer, 8, 0, 0, 0, 0, 0, 7, 0)
	}
	innerStart := len(outer)
	b := append(outer, inner...)
	l3 := innerStart + 14
	l4 := l3 + 20
	if inner6 {
		l4 += 20
	}
	field, kind, constant := 16, "ipv4", l4-14
	var ipcs []uint16
	if outer6 {
		field, kind, constant = 18, "ipv6", l4-54
	} else {
		ipcs = []uint16{14}
	}
	e := &guest.TCPEncapsulation{InnerL3Offset: uint16(l3), InnerL4Offset: uint16(l4), Lengths: []guest.TCPLengthField{{Offset: uint16(field), Kind: kind, Constant: uint16(constant)}, {Offset: uint16(udp + 4), Kind: "udp", Constant: uint16(l4 - udp)}}, IPv4Checksums: ipcs, UDPChecksums: []guest.TCPUDPChecksum{{Offset: uint16(udp), IPOffset: 14, Mode: mode}}, UDPSourcePort: &guest.TCPUDPSourcePort{Offset: uint16(udp), Base: 49152, Count: 16384}}
	return guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: guest.BasePacket{Data: b, Length: uint16(len(b))}, TCPFlow: &guest.TCPFlowVariant{Encapsulation: e, SynOptions: []byte{4, 2, 1, 1}, DataOptions: []byte{1, 1, 1, 1}, Flows: []guest.TCPFlow{{Bytes: "65539"}}}}
}

func tcpMaxGeneveTemplate() guest.PacketVariant {
	v := tcpTestTunnel("geneve", false, false, "lco")
	b := append([]byte(nil), v.Base.Data[:54]...)
	// Existing four-byte option plus 37 more minimum-size options.
	for i := 0; i < 37; i++ {
		b = append(b, 0x12, 0x34, 1, 0)
	}
	b = append(b, v.Base.Data[54:]...)
	b[42] = 38
	v.Base = guest.BasePacket{Data: b, Length: uint16(len(b))}
	e := v.TCPFlow.Encapsulation
	e.InnerL3Offset += 148
	e.InnerL4Offset += 148
	for i := range e.Lengths {
		e.Lengths[i].Constant += 148
	}
	return v
}

// Raw IPv4 saves the inner Ethernet header, allowing 41 minimum options.
func tcpMaxRawGeneveTemplate() guest.PacketVariant {
	v := tcpMaxGeneveTemplate()
	b := append([]byte(nil), v.Base.Data[:202]...)
	for i := 0; i < 3; i++ {
		b = append(b, 0x12, 0x34, 1, 0)
	}
	b = append(b, v.Base.Data[216:]...)
	b[42] = 41
	binary.BigEndian.PutUint16(b[44:], 0x0800)
	v.Base = guest.BasePacket{Data: b, Length: uint16(len(b))}
	e := v.TCPFlow.Encapsulation
	e.InnerL3Offset -= 2
	e.InnerL4Offset -= 2
	for i := range e.Lengths {
		e.Lengths[i].Constant -= 2
	}
	return v
}

func TestTCPEncapValidation(t *testing.T) {
	maxTemplate := tcpMaxGeneveTemplate()
	if maxTemplate.Base.Length != 256 {
		t.Fatal("bad maximum fixture")
	}
	if _, err := parseTCPVariant(maxTemplate); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vxlan", "geneve"} {
		for _, outer6 := range []bool{false, true} {
			for _, inner6 := range []bool{false, true} {
				v := tcpTestTunnel(name, outer6, inner6, "lco")
				if _, err := parseTCPVariant(v); err != nil {
					t.Fatalf("%s %v %v: %v", name, outer6, inner6, err)
				}
			}
		}
	}
	for name, mutate := range map[string]func(*guest.PacketVariant){
		"missing lengths":      func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.Lengths = nil },
		"wrong constant":       func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.Lengths[0].Constant++ },
		"duplicate length":     func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.Lengths[1] = v.TCPFlow.Encapsulation.Lengths[0] },
		"wrong kind":           func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.Lengths[0].Kind = "udp" },
		"missing IP checksum":  func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.IPv4Checksums = nil },
		"missing UDP checksum": func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPChecksums = nil },
		"wrong UDP checksum":   func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPChecksums[0].IPOffset++ },
		"unknown mode":         func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPChecksums[0].Mode = "full" },
		"offset":               func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.InnerL3Offset++ },
		"entropy overlap":      func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPSourcePort.Offset++ },
		"entropy overflow":     func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPSourcePort.Base = 65535 },
		"entropy zero":         func(v *guest.PacketVariant) { v.TCPFlow.Encapsulation.UDPSourcePort.Count = 0 },
		"VXLAN I flag":         func(v *guest.PacketVariant) { v.Base.Data[42] = 0 },
		"unknown tunnel":       func(v *guest.PacketVariant) { binary.BigEndian.PutUint16(v.Base.Data[36:], 9999) },
		"fragment":             func(v *guest.PacketVariant) { v.Base.Data[20] = 0x20 },
		"oversize": func(v *guest.PacketVariant) {
			v.Base.Data = append(v.Base.Data, make([]byte, 256)...)
			v.Base.Length = uint16(len(v.Base.Data))
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := tcpTestTunnel("vxlan", false, false, "zero")
			mutate(&v)
			if _, err := parseTCPVariant(v); err == nil {
				t.Fatal("accepted invalid metadata/header")
			}
		})
	}
	v := tcpTestTunnel("vxlan", true, false, "zero")
	if _, err := parseTCPVariant(v); err == nil {
		t.Fatal("zero IPv6 UDP checksum accepted")
	}
	v = tcpTestTunnel("geneve", false, false, "lco")
	v.Base.Data[52] |= 0x80
	if _, err := parseTCPVariant(v); err == nil {
		t.Fatal("critical GENEVE option accepted")
	}
}

func verifyTCPEncapFrame(t *testing.T, frame []byte, tmpl coreelf.BpfTcpTemplate) {
	t.Helper()
	l3, l4 := int(tmpl.Cfg.L3Off), int(tmpl.Cfg.L4Off)
	if !checksumValid(tmpl.Cfg.PseudoSum + 6 + uint32(len(frame)-l4) + checksumSum(frame[l4:])) {
		t.Fatal("invalid inner TCP checksum")
	}
	if tmpl.Cfg.IpVersion == 4 && !checksumValid(checksumSum(frame[l3:l3+20])) {
		t.Fatal("invalid inner IP checksum")
	}
	for i := 0; i < int(tmpl.LengthCount); i++ {
		p := tmpl.Lengths[i]
		if got := int(binary.BigEndian.Uint16(frame[p.Offset:])); got != int(p.Constant)+len(frame)-l4 {
			t.Fatalf("length %d=%d", p.Offset, got)
		}
	}
	for i := 0; i < int(tmpl.OuterIpCount); i++ {
		p := tmpl.OuterIps[i]
		if p.Version == 4 && tmpl.Cfg.IpIdShared != 0 && tmpl.Cfg.IpVersion == 4 && !bytes.Equal(frame[int(p.Offset)+4:int(p.Offset)+6], frame[l3+4:l3+6]) {
			t.Fatal("shared outer IP ID")
		}
		if p.Version == 4 && !checksumValid(checksumSum(frame[p.Offset:int(p.Offset)+20])) {
			t.Fatal("outer IPv4 checksum")
		}
	}
	for i := 0; i < int(tmpl.UdpCount); i++ {
		u := tmpl.Udps[i]
		off := int(u.Offset)
		if u.Mode == 0 {
			if binary.BigEndian.Uint16(frame[off+6:]) != 0 {
				t.Fatal("nonzero disabled checksum")
			}
		} else if !checksumValid(u.PseudoSum + 17 + uint32(len(frame)-off) + checksumSum(frame[off:])) {
			t.Fatalf("outer UDP LCO mismatch at %d", off)
		}
	}
}

func TestTCPEncapBPF(t *testing.T)        { testTCPEncapBPF(t, "all") }
func TestTCPRawGeneveBPF(t *testing.T)    { testTCPEncapBPF(t, "raw-geneve") }
func TestTCPZeroUDPEncapBPF(t *testing.T) { testTCPEncapBPF(t, "zero") }
func TestTCPMPLSOnlyBPF(t *testing.T)     { testTCPEncapBPF(t, "mpls") }

func testTCPEncapBPF(t *testing.T, profile string) {
	objs, spec, err := coreelf.ReadBaseCollectionWithSizes(map[string]any{"swap_resp": uint32(0)}, map[string]uint32{"diff_map": 100})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfobjs: objs, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	x.cfg.TCPIPID = "shared"
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[:1]
	for _, name := range []string{"vxlan", "geneve"} {
		for _, outer6 := range []bool{false, true} {
			for _, inner6 := range []bool{false, true} {
				r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, tcpTestTunnel(name, outer6, inner6, "lco"))
			}
		}
	}
	r.VariablePacketTemplate.Variants[1].TCPFlow.Encapsulation.UDPChecksums[0].Mode = "zero"
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, tcpMaxGeneveTemplate())
	for _, name := range []string{"ipip", "gre", "srv6", "gtpu", "mpls", "nested"} {
		r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, tcpOtherTunnel(name))
	}
	if profile == "raw-geneve" {
		r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], tcpMaxRawGeneveTemplate())
	} else if profile == "zero" {
		r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], tcpTestTunnel("vxlan", false, false, "zero"))
	} else if profile == "mpls" {
		r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], tcpOtherTunnel("mpls"))
	}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if profile == "zero" && (x.mixed.features.LCO || x.mixed.features.UDPs != 1) {
		t.Fatalf("expected UDP fixups without LCO: %+v", x.mixed.features)
	}
	if profile == "mpls" && x.mixed.features != (coreelf.MixedProgramFeatures{}) {
		t.Fatalf("MPLS-only template must not require envelope edits: %+v", x.mixed.features)
	}
	if err := coreelf.LoadMixedProgramsWithFeatures(objs, spec, x.mixed.features); err != nil {
		t.Fatal(err)
	}
	target, err := parseTCPVariant(x.mixed.groups[0].variant)
	if err != nil {
		t.Fatal(err)
	}
	target.mss = 1024
	if err := x.initTCPMaps(target, x.mixed.groups[0].variant.Base.Data); err != nil {
		t.Fatal(err)
	}
	states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
	for i := range x.mixed.groups {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var tmpl coreelf.BpfTcpTemplate
			if err := objs.TcpTemplateMap.Lookup(uint32(i), &tmpl); err != nil {
				t.Fatal(err)
			}
			for k := range states {
				states[k].SelectedFlow = uint32(i)
			}
			if err := objs.MixedStateMap.Put(uint32(0), states); err != nil {
				t.Fatal(err)
			}
			for _, syn := range []bool{true, false} {
				f := coreelf.BpfTcpFlow{TemplateId: uint32(i), State: tcpFlowEstablished, SrcPort: uint16(40000 + i), Iss: 100, SndUna: 101, SndNxt: 101, SndMax: 101, RcvNxt: 5001, SndWnd: 65535, Mss: tmpl.Cfg.Mss, BytesTarget: 3}
				if syn {
					f.State = tcpFlowClosed
				}
				if err := objs.TcpFlowMap.Put(uint32(i), f); err != nil {
					t.Fatal(err)
				}
				action, frame, err := objs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
				if err != nil || action != 3 {
					t.Fatalf("TX %d %v", action, err)
				}
				verifyTCPEncapFrame(t, frame, tmpl)
				if profile == "mpls" {
					if !bytes.Equal(frame[:tmpl.Cfg.L3Off], tmpl.Prefix[:tmpl.Cfg.L3Off]) {
						t.Fatal("MPLS/Ethernet prefix changed")
					}
					wantLen := int(tmpl.Cfg.L4Off) + 20 + int(tmpl.DataLen) + 3
					if syn {
						wantLen = int(tmpl.Cfg.L4Off) + 20 + int(tmpl.SynLen)
					}
					if len(frame) != wantLen {
						t.Fatalf("MPLS frame length = %d, want %d", len(frame), wantLen)
					}
				}
				if tmpl.EntropyCount != 0 && binary.BigEndian.Uint16(frame[tmpl.EntropyOffset:]) != uint16(49152+i) {
					t.Fatal("flow entropy")
				}
				if !syn {
					if !bytes.Equal(frame[len(frame)-3:], []byte{0, 0, 0}) {
						t.Fatal("payload contamination")
					}
					continue
				}
				l3, l4 := int(tmpl.Cfg.L3Off), int(tmpl.Cfg.L4Off)
				addrStart, addrLen := l3+12, 4
				if tmpl.Cfg.IpVersion == 6 {
					addrStart, addrLen = l3+8, 16
				}
				tmp := append([]byte(nil), frame[addrStart:addrStart+addrLen]...)
				copy(frame[addrStart:addrStart+addrLen], frame[addrStart+addrLen:addrStart+2*addrLen])
				copy(frame[addrStart+addrLen:], tmp)
				binary.BigEndian.PutUint16(frame[l4:], tmpl.Cfg.DstPort)
				binary.BigEndian.PutUint16(frame[l4+2:], uint16(40000+i))
				binary.BigEndian.PutUint32(frame[l4+4:], 5000)
				binary.BigEndian.PutUint32(frame[l4+8:], 101)
				frame[l4+13] = 0x12
				// Outer tuple/VNI intentionally remain in the TX direction; they are not keys.
				action, reply, err := objs.XdpRxTcpMixed.Test(frame)
				if err != nil || action != 3 {
					t.Fatalf("encap RX %d %v", action, err)
				}
				verifyTCPEncapFrame(t, reply, tmpl)
				if tmpl.UdpCount > 0 {
					// A shorter UDP envelope must not expose the inner TCP carried in padding.
					bad := append([]byte(nil), frame...)
					binary.BigEndian.PutUint16(bad[int(tmpl.Udps[0].Offset)+4:], 8)
					action, _, err = objs.XdpRxTcpMixed.Test(bad)
					if err != nil || action != 2 {
						t.Fatalf("short parent UDP %d %v", action, err)
					}
				}
				// Bare responses accepted; the configured outer envelope is restored.
				bare := append([]byte(nil), tcpTestBase(tmpl.Cfg.IpVersion == 6, 0).Data[:14]...)
				bare = append(bare, frame[l3:]...)
				action, reply, err = objs.XdpRxTcpMixed.Test(bare)
				if err != nil || action != 3 {
					t.Fatalf("bare RX %d %v", action, err)
				}
				verifyTCPEncapFrame(t, reply, tmpl)
			}
		})
	}
}

func tcpOtherTunnel(name string) guest.PacketVariant {
	inner := tcpTestBase(false, 0).Data[14:]
	b := append([]byte(nil), tcpTestBase(false, 0).Data[:34]...)
	e := &guest.TCPEncapsulation{}
	switch name {
	case "ipip":
		b[23] = 4
	case "gre":
		b[23] = 47
		b = append(b, 0x20, 0, 8, 0, 0, 0, 0, 7)
	case "srv6":
		b = append([]byte(nil), tcpTestBase(true, 0).Data[:54]...)
		b[20] = 43
		b = append(b, 4, 2, 4, 0, 0, 0, 0, 0)
		b = append(b, net.ParseIP("2001:db8::2").To16()...)
	case "gtpu":
		b[23] = 17
		b = append(b, 0xc0, 0, 8, 0x68, 0, 0, 0, 0, 0x30, 0xff, 0, 0, 0, 0, 0, 7)
	case "mpls":
		b = b[:14]
		binary.BigEndian.PutUint16(b[12:], 0x8847)
		b = append(b, 0, 1, 1, 64)
	case "nested":
		v := tcpTestTunnel("vxlan", false, false, "lco")
		b = append([]byte(nil), v.Base.Data[:50]...)
		b = append(b, v.Base.Data...)
		e = &guest.TCPEncapsulation{InnerL3Offset: 114, InnerL4Offset: 134, Lengths: []guest.TCPLengthField{{Offset: 16, Kind: "ipv4", Constant: 120}, {Offset: 38, Kind: "udp", Constant: 100}, {Offset: 66, Kind: "ipv4", Constant: 70}, {Offset: 88, Kind: "udp", Constant: 50}}, IPv4Checksums: []uint16{14, 64}, UDPChecksums: []guest.TCPUDPChecksum{{Offset: 34, IPOffset: 14, Mode: "lco"}, {Offset: 84, IPOffset: 64, Mode: "lco"}}}
		return guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: guest.BasePacket{Data: b, Length: uint16(len(b))}, TCPFlow: &guest.TCPFlowVariant{Encapsulation: e, Flows: []guest.TCPFlow{{Bytes: "65539"}}}}
	}
	l3, l4 := len(b), len(b)+20
	b = append(b, inner...)
	e.InnerL3Offset, e.InnerL4Offset = uint16(l3), uint16(l4)
	if name == "srv6" {
		e.Lengths = []guest.TCPLengthField{{Offset: 18, Kind: "ipv6", Constant: uint16(l4 - 54)}}
	} else if name != "mpls" {
		e.Lengths = []guest.TCPLengthField{{Offset: 16, Kind: "ipv4", Constant: uint16(l4 - 14)}}
		e.IPv4Checksums = []uint16{14}
	}
	if name == "gtpu" {
		e.Lengths = append(e.Lengths, guest.TCPLengthField{Offset: 38, Kind: "udp", Constant: uint16(l4 - 34)}, guest.TCPLengthField{Offset: 44, Kind: "gtpu", Constant: uint16(l4 - 50)})
		e.UDPChecksums = []guest.TCPUDPChecksum{{Offset: 34, IPOffset: 14, Mode: "lco"}}
	}
	return guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: guest.BasePacket{Data: b, Length: uint16(len(b))}, TCPFlow: &guest.TCPFlowVariant{Encapsulation: e, Flows: []guest.TCPFlow{{Bytes: "65539"}}}}
}

func TestTCPKnownTunnelParsers(t *testing.T) {
	for _, name := range []string{"ipip", "gre", "srv6", "gtpu", "mpls", "nested"} {
		t.Run(name, func(t *testing.T) {
			v := tcpOtherTunnel(name)
			if _, err := parseTCPVariant(v); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMixedUDPOptionsAccounting(t *testing.T) {
	objs, _, err := coreelf.ReadCollection(map[string]any{"swap_resp": uint32(0)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	if err := objs.MixedCfgMap.Put(uint32(0), coreelf.BpfMixedCfg{Receive: 1}); err != nil {
		t.Fatal(err)
	}
	packet := append([]byte(nil), tcpTestBase(false, 0).Data[:34]...)
	packet[14] = 0x46
	packet[23] = 17
	packet = append(packet, 1, 1, 1, 1, 0xc0, 0, 0x27, 0x10, 0, 8, 0, 0)
	binary.BigEndian.PutUint16(packet[16:], uint16(len(packet)-14))
	for _, receiver := range []bool{true, false} {
		t.Run(fmt.Sprint(receiver), func(t *testing.T) {
			var cfg coreelf.BpfMixedCfg
			if receiver {
				cfg.Receive = 1
			}
			if err := objs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
				t.Fatal(err)
			}
			before := make([]coreelf.BpfDatarec, ebpf.MustPossibleCPU())
			if err := objs.RxStatsMap.Lookup(uint32(0), &before); err != nil {
				t.Fatal(err)
			}
			action, _, err := objs.XdpRxMixed.Test(packet)
			wantAction := uint32(2)
			if receiver {
				wantAction = 1
			} // The legacy receiver counts and drops.
			if err != nil || action != wantAction {
				t.Fatalf("action=%d err=%v", action, err)
			}
			after := make([]coreelf.BpfDatarec, len(before))
			if err := objs.RxStatsMap.Lookup(uint32(0), &after); err != nil {
				t.Fatal(err)
			}
			var packets, nbytes uint64
			for i := range after {
				packets += after[i].Packets - before[i].Packets
				nbytes += after[i].Bytes - before[i].Bytes
			}
			want := uint64(0)
			if receiver {
				want = 1
			}
			if packets != want || nbytes != want*uint64(len(packet)) {
				t.Fatalf("packets=%d bytes=%d", packets, nbytes)
			}
		})
	}
}

func TestTCPGRESequenceRejected(t *testing.T) {
	for _, key := range []bool{false, true} {
		t.Run(fmt.Sprint(key), func(t *testing.T) {
			v := tcpOtherTunnel("gre")
			v.Base.Data[34] = 0x10
			if key {
				v.Base.Data[34] |= 0x20
				b := append([]byte(nil), v.Base.Data[:42]...)
				b = append(b, 0, 0, 0, 9)
				b = append(b, v.Base.Data[42:]...)
				v.Base = guest.BasePacket{Data: b, Length: uint16(len(b))}
				e := v.TCPFlow.Encapsulation
				e.InnerL3Offset += 4
				e.InnerL4Offset += 4
				for i := range e.Lengths {
					e.Lengths[i].Constant += 4
				}
			}
			if _, err := parseTCPVariant(v); err == nil || !strings.Contains(err.Error(), "sequence unsupported") {
				t.Fatalf("sequence accepted or wrong validation: %v", err)
			}
		})
	}
}

func TestTCPGTPSequenceRejected(t *testing.T) {
	for _, flags := range []byte{1, 2, 3, 5, 6, 7} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			v := tcpOtherTunnel("gtpu")
			b := append([]byte(nil), v.Base.Data[:50]...)
			b[42] |= flags
			b = append(b, 0, 9, 7, 0)
			b = append(b, v.Base.Data[50:]...)
			v.Base = guest.BasePacket{Data: b, Length: uint16(len(b))}
			e := v.TCPFlow.Encapsulation
			e.InnerL3Offset += 4
			e.InnerL4Offset += 4
			for i := range e.Lengths {
				e.Lengths[i].Constant += 4
			}
			if _, err := parseTCPVariant(v); err == nil || !strings.Contains(err.Error(), "GTP-U sequence/N-PDU numbering unsupported") {
				t.Fatalf("numbering accepted or wrong validation: %v", err)
			}
		})
	}
}

func TestMixedTunnelNeighborPass(t *testing.T) {
	objs, _, err := coreelf.ReadCollection(map[string]any{"swap_resp": uint32(0)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	if err := objs.MixedCfgMap.Put(uint32(0), coreelf.BpfMixedCfg{Receive: 1}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vxlan", "geneve"} {
		for _, nd := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nd=%v", name, nd), func(t *testing.T) {
				v := tcpTestTunnel(name, false, nd, "zero")
				l3 := int(v.TCPFlow.Encapsulation.InnerL3Offset)
				frame := append([]byte(nil), v.Base.Data[:l3]...)
				if nd {
					frame = append(frame, v.Base.Data[l3:l3+40]...)
					frame[l3+6] = 58
					frame = append(frame, make([]byte, 24)...)
					frame[l3+40] = 135
					binary.BigEndian.PutUint16(frame[l3+4:], 24)
				} else {
					binary.BigEndian.PutUint16(frame[l3-2:], 0x0806)
					frame = append(frame, make([]byte, 28)...)
					copy(frame[l3:], []byte{0, 1, 8, 0, 6, 4, 0, 1})
				}
				binary.BigEndian.PutUint16(frame[16:], uint16(len(frame)-14))
				binary.BigEndian.PutUint16(frame[38:], uint16(len(frame)-34))
				action, _, err := objs.XdpRxMixed.Test(frame)
				if err != nil || action != 2 {
					t.Fatalf("neighbor action=%d err=%v", action, err)
				}
			})
		}
	}
	stats := make([]coreelf.BpfDatarec, ebpf.MustPossibleCPU())
	if err := objs.RxStatsMap.Lookup(uint32(0), &stats); err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		if s.Packets != 0 {
			t.Fatal("neighbor traffic counted as UDP")
		}
	}
}
