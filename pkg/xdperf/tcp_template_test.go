package xdperf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

func tcpTestBase(v6 bool, tags int) guest.BasePacket {
	l3 := 14 + tags*4
	iplen, proto := 20, uint16(0x0800)
	if v6 {
		iplen, proto = 40, 0x86dd
	}
	b := make([]byte, l3+iplen+20)
	copy(b, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	for i := 0; i < tags; i++ {
		binary.BigEndian.PutUint16(b[12+i*4:], 0x8100)
		binary.BigEndian.PutUint16(b[14+i*4:], uint16(110+i))
	}
	binary.BigEndian.PutUint16(b[l3-2:], proto)
	if v6 {
		b[l3], b[l3+1], b[l3+2], b[l3+3] = 0x6a, 0xf1, 0x23, 0x45
		b[l3+6], b[l3+7] = 6, 37
		copy(b[l3+8:], net.ParseIP("2001:db8::1").To16())
		copy(b[l3+24:], net.ParseIP("2001:db8::2").To16())
	} else {
		b[l3], b[l3+1], b[l3+4], b[l3+5], b[l3+8], b[l3+9] = 0x45, 0xab, 0x12, 0x34, 37, 6
		copy(b[l3+12:], net.ParseIP("192.0.2.1").To4())
		copy(b[l3+16:], net.ParseIP("192.0.2.2").To4())
	}
	binary.BigEndian.PutUint16(b[l3+iplen+2:], 5201)
	b[l3+iplen+12] = 0x50
	b[l3+iplen+19] = 7 // plugin-owned urgent pointer
	return guest.BasePacket{Data: b, Length: uint16(len(b))}
}

func TestTCPBaseValidation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for tags := 0; tags <= 2; tags++ {
			b := tcpTestBase(v6, tags)
			tt, err := parseTCPBase(b)
			if err != nil || int(tt.l3Off) != 14+tags*4 {
				t.Fatalf("v6=%v tags=%d: %v", v6, tags, err)
			}
		}
	}
	for name, mutate := range map[string]func(*guest.BasePacket){
		"length":   func(b *guest.BasePacket) { b.Length-- },
		"short":    func(b *guest.BasePacket) { b.Data = b.Data[:12]; b.Length = 12 },
		"version":  func(b *guest.BasePacket) { b.Data[14] = 0x65 },
		"options":  func(b *guest.BasePacket) { b.Data[14] = 0x46 },
		"fragment": func(b *guest.BasePacket) { b.Data[20] = 0x20 },
		"udp":      func(b *guest.BasePacket) { b.Data[23] = 17 },
		"payload":  func(b *guest.BasePacket) { b.Data = append(b.Data, 0); b.Length++ },
		"port":     func(b *guest.BasePacket) { b.Data[36] = 0; b.Data[37] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := tcpTestBase(false, 0)
			mutate(&b)
			if _, err := parseTCPBase(b); err == nil {
				t.Fatal("accepted invalid base")
			}
		})
	}
	r := mixedResponse()
	v := &r.VariablePacketTemplate.Variants[1]
	v.Base = tcpTestBase(false, 2)
	v.TCPFlow.Destination = ""
	x := &Xdperf{cfg: mixedConfig()}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if x.cfg.TCPDst != "192.0.2.2:5201" {
		t.Fatal(x.cfg.TCPDst)
	}
	v.TCPFlow.Destination = "192.0.2.3:5201"
	x = &Xdperf{cfg: mixedConfig()}
	if x.prepareMixed(r) == nil {
		t.Fatal("accepted mismatched destination")
	}
}

func TestTCPStaticOptions(t *testing.T) {
	good := [][]byte{nil, {1}, {4, 2}, {0, 0}, {254, 4, 0xab, 0xcd}}
	for _, b := range good {
		if got, e := tcpStaticOptions(b, true); e != nil || len(got)%4 != 0 || !bytes.Equal(got[:len(b)], b) {
			t.Fatalf("%x: %x %v", b, got, e)
		}
	}
	for _, syn := range []bool{false, true} {
		for _, input := range [][]byte{{0}, {0, 0}, {1, 0}, {254, 2, 0}} {
			got, err := tcpStaticOptions(input, syn)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[len(input):], make([]byte, len(got)-len(input))) {
				t.Fatalf("nonzero EOL padding: %x", got)
			}
			if _, err := tcpStaticOptions(got, syn); err != nil {
				t.Fatal(err)
			}
		}
	}

	bad := [][]byte{{2, 4, 0, 0}, {3, 3, 7}, {8, 10, 0, 0, 0, 0, 0, 0, 0, 0}, {30, 2}, {34, 2}, {19, 2}, {29, 2}, {5, 2}, {254}, {254, 1}, {254, 5, 0, 0}, {0, 1}, bytes.Repeat([]byte{1}, 33)}
	for _, b := range bad {
		if _, err := tcpStaticOptions(b, true); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	if _, err := tcpStaticOptions([]byte{4, 2}, false); err == nil {
		t.Fatal("SACK permitted in data")
	}
}

func checksumSum(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	return s
}
func checksumValid(sum uint32) bool {
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return sum == 65535
}

func TestTCPTemplateBPF(t *testing.T) {
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[:1]
	for _, v6 := range []bool{false, true} {
		for tags := 0; tags <= 2; tags++ {
			base := tcpTestBase(v6, tags)
			binary.BigEndian.PutUint16(base.Data[len(base.Data)-18:], uint16(5201+tags))
			r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: base, TCPFlow: &guest.TCPFlowVariant{SynOptions: []byte{4, 2, 1, 1}, DataOptions: []byte{254, 4, 0xab, 0xcd}, Flows: []guest.TCPFlow{{Bytes: "101"}}}})
		}
	}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	objs := loadMixedTestObjects(t, x.mixed.features)
	x.bpfobjs = objs
	base := r.VariablePacketTemplate.Variants[1].Base
	target, _ := parseTCPBase(base)
	target.mss = 1024
	if err := x.initTCPMaps(target, base.Data); err != nil {
		t.Fatal(err)
	}
	for i, g := range x.mixed.groups {
		var tmpl coreelf.BpfTcpTemplate
		if err := objs.TcpTemplateMap.Lookup(uint32(i), &tmpl); err != nil {
			t.Fatal(err)
		}
		tt, _ := parseTCPBase(g.variant.Base)
		selectMixedTestFlow(t, objs, uint32(i))
		for _, kind := range []string{"syn", "data", "tail", "fin", "retransmit"} {
			f := coreelf.BpfTcpFlow{TemplateId: uint32(i), State: tcpFlowEstablished, SrcPort: uint16(40000 + i), Iss: 100, SndUna: 101, SndNxt: 101, SndMax: 101, RcvNxt: 5001, SndWnd: 65535, Mss: tmpl.Cfg.Mss, BytesTarget: 101, IpId: 0x1234}
			opts, wantLen, flags := 4, 101, byte(0x18)
			switch kind {
			case "syn":
				f.State = tcpFlowClosed
				opts, wantLen, flags = 12, 0, 2
			case "tail":
				f.BytesTarget = 1
				wantLen = 1
			case "fin":
				f.BytesTarget = 1
				f.BytesAcked = 1
				f.SndUna = 102
				f.SndNxt = 102
				f.SndMax = 102
				wantLen, flags = 0, 0x11
			case "retransmit":
				f.SndMax = 202
				f.RtxPending = 1
			}
			if err := objs.TcpFlowMap.Put(uint32(i), f); err != nil {
				t.Fatal(err)
			}
			action, out, err := objs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
			if err != nil {
				t.Fatal(err)
			}
			l3, l4 := int(tt.l3Off), int(tt.l4Off)
			if action != 3 || len(out) != l4+20+opts+wantLen {
				t.Fatalf("group %d %s action %d length %d", i, kind, action, len(out))
			}
			if out[l4+13] != flags {
				t.Fatalf("%s flags %x", kind, out[l4+13])
			}
			if !bytes.Equal(out[:l3], g.variant.Base.Data[:l3]) || out[l4+19] != 7 {
				t.Fatal("plugin bytes lost")
			}
			if tt.ipVersion == 4 {
				if out[l3+1] != 0xa8 || out[l3+8] != 37 || !checksumValid(checksumSum(out[l3:l4])) {
					t.Fatal("IPv4 fields/checksum")
				}
			} else if !bytes.Equal(out[l3:l3+4], []byte{0x6a, 0xc1, 0x23, 0x45}) || out[l3+7] != 37 {
				t.Fatal("IPv6 fields")
			}
			sum := pseudoHeaderAddrSum(tt.srcIP, tt.dstIP) + 6 + uint32(len(out)-l4) + checksumSum(out[l4:])
			if !checksumValid(sum) {
				t.Fatalf("group %d %s TCP checksum", i, kind)
			}
			if !bytes.Equal(out[l4+20+opts:], make([]byte, wantLen)) {
				t.Fatal("payload contaminated")
			}
			if kind == "syn" {
				// A bare SYN-ACK must be accepted even if TX uses QinQ.
				reply := tcpTestBase(tt.ipVersion == 6, 0).Data
				rl4 := 34
				if tt.ipVersion == 6 {
					rl4 = 54
				}
				if tt.ipVersion == 4 {
					copy(reply[26:30], tt.dstIP)
					copy(reply[30:34], tt.srcIP)
					binary.BigEndian.PutUint16(reply[16:], 40)
				} else {
					copy(reply[22:38], tt.dstIP)
					copy(reply[38:54], tt.srcIP)
					binary.BigEndian.PutUint16(reply[18:], 20)
				}
				binary.BigEndian.PutUint16(reply[rl4:], tt.dstPort)
				binary.BigEndian.PutUint16(reply[rl4+2:], uint16(40000+i))
				binary.BigEndian.PutUint32(reply[rl4+4:], 5000)
				binary.BigEndian.PutUint32(reply[rl4+8:], 101)
				reply[rl4+12], reply[rl4+13] = 0x50, 0x12
				binary.BigEndian.PutUint16(reply[rl4+14:], 65535)
				action, ack, err := objs.XdpRxTcpMixed.Test(reply)
				if err != nil || action != 3 {
					t.Fatalf("RX %d: %d %v", i, action, err)
				}
				if len(ack) != l4+24 || ack[l4+13] != 0x10 || !bytes.Equal(ack[:l3], g.variant.Base.Data[:l3]) {
					t.Fatal("RX did not use group template")
				}
				if !checksumValid(pseudoHeaderAddrSum(tt.srcIP, tt.dstIP) + 6 + 24 + checksumSum(ack[l4:])) {
					t.Fatal("ACK checksum")
				}
				reply[rl4+12] = 0xf0
				action, _, err = objs.XdpRxTcpMixed.Test(reply)
				if err != nil || action != 1 {
					t.Fatalf("invalid TCP length: %d %v", action, err)
				}
				reply[rl4+12] = 0x50
				binary.BigEndian.PutUint16(reply[rl4:], tt.dstPort+1)
				action, _, err = objs.XdpRxTcpMixed.Test(reply)
				if err != nil || action != 2 {
					t.Fatalf("wrong tuple: %d %v", action, err)
				}

			}
		}
	}
}

func TestTCPTemplateMSS(t *testing.T) {
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                             string
		v6                               bool
		tags, mtu, requested, opts, want int
		bad                              bool
	}{
		{"v4 default", false, 0, 1500, 0, 0, 1448, false},
		{"v6 options", true, 0, 1500, 0, 40, 1388, false},
		{"QinQ options", false, 2, 1500, 0, 4, 1436, false},
		{"small MTU", false, 0, 1280, 0, 4, 1236, false},
		{"explicit", false, 0, 1500, 1024, 4, 1020, false},
		{"minimum", false, 0, 1500, 68, 4, 64, false},
		{"below minimum", false, 0, 1500, 67, 4, 0, true},
		{"MTU boundary", false, 0, 104, 0, 0, 64, false},
		{"too small MTU", false, 0, 103, 0, 0, 0, true},
		{"explicit over MTU", false, 0, 1000, 1024, 0, 0, true},
		{"QinQ exceeds frame MTU", false, 2, 1500, 1460, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: tc.mtu}, bpfSpec: spec}
			x.cfg.TCPMSS = tc.requested
			target, err := parseTCPBase(tcpTestBase(tc.v6, tc.tags))
			if err != nil {
				t.Fatal(err)
			}
			err = x.templateMSS(target, x.cfg.TCPMSS, tc.opts)
			if (err != nil) != tc.bad || (!tc.bad && int(target.mss) != tc.want) {
				t.Fatalf("MSS %d err %v, want %d error %v", target.mss, err, tc.want, tc.bad)
			}
		})
	}
}

func TestTCPGroupKnobsBPF(t *testing.T) {
	for _, explicitBase := range []bool{false, true} {
		t.Run(fmt.Sprint("base=", explicitBase), func(t *testing.T) {
			spec, err := coreelf.LoadBpf()
			if err != nil {
				t.Fatal(err)
			}
			dev, err := net.InterfaceByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			dev.MTU = 1500
			dev.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
			x := &Xdperf{cfg: mixedConfig(), Device: dev, bpfSpec: spec, cpus: []int{0, 1}, Logger: zap.NewNop()}
			x.cfg.Parallelism = 2
			x.cfg.TCPWindow, x.cfg.TCPMSS, x.cfg.TCPRTO, x.cfg.TCPIPID = 11, 1200, 450*time.Millisecond, "shared"
			if !explicitBase {
				x.cfg.TCPDstMAC = "02:00:00:00:00:02"
			}
			r := &guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeVariable,
				VariablePacketTemplate: guest.PacketVariantSet{Pattern: guest.VariantSelectionModeMixed, TCPPortBase: 12001}}
			for i := range 2 {
				f := &guest.TCPFlowVariant{Destination: fmt.Sprintf("127.0.0.%d:5201", i+2),
					DataOptions: []byte{1, 1, 1, 1}, Flows: []guest.TCPFlow{{Bytes: "1000"}}}
				if i == 0 {
					f.WindowSegs, f.MSS, f.RTOMillis, f.IPID = 3, 900, 75, "flow"
				}
				v := guest.PacketVariant{Kind: "tcp_flow", Weight: 1, TCPFlow: f}
				if explicitBase {
					v.Base = tcpTestBase(false, 0)
					v.Base.Data[33] += byte(i)
					f.Destination = ""
				}
				r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, v)
			}
			if err := x.prepareMixed(r); err != nil {
				t.Fatal(err)
			}
			x.bpfobjs = loadMixedTestObjects(t, x.mixed.features)
			var target *tcpTarget
			var frame []byte
			if explicitBase {
				target, err = parseTCPBase(x.mixed.groups[0].variant.Base)
				frame = x.mixed.groups[0].variant.Base.Data
			} else {
				resolver := &Xdperf{cfg: x.cfg, Device: dev, bpfSpec: spec, Logger: x.Logger}
				resolver.cfg.TCPMSS = x.mixed.groups[0].mss
				target, err = resolver.resolveTCPTarget()
				if err == nil {
					frame, err = buildTCPTemplate(target, uint16(x.cfg.TCPPortBase))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := x.initTCPMaps(target, frame); err != nil {
				t.Fatal(err)
			}
			if err := x.initMixedMaps(); err != nil {
				t.Fatal(err)
			}
			var global coreelf.BpfTcpCfg
			if err := x.bpfobjs.TcpCfgMap.Lookup(uint32(0), &global); err != nil {
				t.Fatal(err)
			}
			if global.PortBase != 12001 || global.FlowCount != 2 {
				t.Fatalf("global port range: %+v", global)
			}
			for i := uint32(0); i < 2; i++ {
				var tmpl coreelf.BpfTcpTemplate
				if err := x.bpfobjs.TcpTemplateMap.Lookup(i, &tmpl); err != nil {
					t.Fatal(err)
				}
				wantMSS, wantWindow, wantRTO, wantID := uint16(896), uint32(3), uint64(75*time.Millisecond), uint8(0)
				if i == 1 {
					wantMSS, wantWindow, wantRTO, wantID = 1196, 11, uint64(450*time.Millisecond), 1
				}
				if tmpl.Cfg.Mss != wantMSS || tmpl.Cfg.WindowSegs != wantWindow || tmpl.Cfg.RtoNs != wantRTO || tmpl.Cfg.IpIdShared != wantID {
					t.Fatalf("group %d settings: %+v", i, tmpl.Cfg)
				}
				selectMixedTestFlow(t, x.bpfobjs, i)
				action, out, err := x.bpfobjs.XdpTxTcpMixed.Test(make([]byte, 2049))
				l4 := int(tmpl.Cfg.L4Off)
				if err != nil || action != 3 {
					t.Fatalf("TX %d: action=%d err=%v", i, action, err)
				}
				if binary.BigEndian.Uint16(out[l4:]) != 12001+uint16(i) || binary.BigEndian.Uint16(out[l4+22:]) != wantMSS {
					t.Fatalf("TX %d lost port base or MSS", i)
				}
				flows, err := x.readTCPFlows(2)
				if err != nil {
					t.Fatal(err)
				}
				f := flows[i]
				if f.SrcPort != 12001+uint16(i) {
					t.Fatalf("flow %d source port: %d", i, f.SrcPort)
				}
				// Complete via RX and check PR1's worker slot derived from port base.
				f.State, f.SndUna, f.SndNxt, f.SndMax, f.RcvNxt = tcpFlowFinWait2, 101, 101, 101, 5001
				if err := x.bpfobjs.TcpFlowMap.Put(i, f); err != nil {
					t.Fatal(err)
				}
				reply := tcpTestBase(false, 0).Data
				copy(reply[26:30], out[30:34])
				copy(reply[30:34], out[26:30])
				binary.BigEndian.PutUint16(reply[16:], 40)
				binary.BigEndian.PutUint16(reply[34:], tmpl.Cfg.DstPort)
				binary.BigEndian.PutUint16(reply[36:], f.SrcPort)
				binary.BigEndian.PutUint32(reply[38:], 5001)
				binary.BigEndian.PutUint32(reply[42:], 101)
				reply[47] = 0x11
				action, _, err = x.bpfobjs.XdpRxTcpMixed.Test(reply)
				if err != nil || action != 3 {
					t.Fatalf("RX %d: action=%d err=%v", i, action, err)
				}
				if err := x.bpfobjs.TcpFlowMap.Lookup(i, &f); err != nil {
					t.Fatal(err)
				}
				var closed uint32
				if err := x.bpfobjs.MixedClosedMap.Lookup(i, &closed); err != nil {
					t.Fatal(err)
				}
				if f.State != tcpFlowDone || closed != 1 {
					t.Fatalf("RX %d state=%d closed=%d", i, f.State, closed)
				}
			}
		})
	}
}
