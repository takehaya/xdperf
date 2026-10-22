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
	"golang.org/x/sys/unix"
)

func setupFlowExtensions(t *testing.T, variants ...guest.PacketVariant) *Xdperf {
	t.Helper()
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], variants...)
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	x.bpfobjs = loadMixedTestObjects(t, x.mixed.features)
	target, err := parseTCPVariant(variants[0])
	if err != nil {
		t.Fatal(err)
	}
	target.mss = 1024
	if err := x.initTCPMaps(target, variants[0].Base.Data); err != nil {
		t.Fatal(err)
	}
	return x
}

func selectExtensionFlow(t *testing.T, x *Xdperf, idx uint32, f coreelf.BpfTcpFlow) {
	t.Helper()
	if err := x.bpfobjs.TcpFlowMap.Put(idx, f); err != nil {
		t.Fatal(err)
	}
	selectMixedTestFlow(t, x.bpfobjs, idx)
}

// Direct TX tests select one flow on every CPU without running the dispatcher.
func selectMixedTestFlow(t *testing.T, objs *coreelf.BpfObjects, idx uint32) {
	t.Helper()
	n := ebpf.MustPossibleCPU()
	states := make([]coreelf.BpfMixedState, n)
	groups := make([]coreelf.BpfMixedGroup, n)
	cpus := make([]coreelf.BpfTcpCpuState, n)
	if err := objs.TcpCpuStateMap.Lookup(uint32(0), &cpus); err != nil {
		t.Fatal(err)
	}
	for i := range states {
		groups[i] = coreelf.BpfMixedGroup{First: idx, Count: 1}
		cpus[i].First, cpus[i].Count, cpus[i].Stride, cpus[i].Cursor = idx, 1, 1, 0
	}
	if err := objs.MixedGroupMap.Put(uint32(0), groups); err != nil {
		t.Fatal(err)
	}
	if err := objs.TcpCpuStateMap.Put(uint32(0), cpus); err != nil {
		t.Fatal(err)
	}
	if err := objs.MixedStateMap.Put(uint32(0), states); err != nil {
		t.Fatal(err)
	}
}

func extensionVariant(v6 bool) guest.PacketVariant {
	return guest.PacketVariant{Kind: "tcp_flow", Weight: 1, Base: tcpTestBase(v6, 0), TCPFlow: &guest.TCPFlowVariant{Flows: []guest.TCPFlow{{Bytes: "10000"}}}}
}

func TestTCPPayloadBPF(t *testing.T) {
	// Odd periods, offsets and lengths exercise checksum byte-phase changes.
	for _, v6 := range []bool{false, true} {
		for _, pattern := range [][]byte{{0}, {0xa7}, {0x12, 0x34}, {0x01, 0x23, 0xfe}, bytes.Repeat([]byte{0xff}, 255), append(bytes.Repeat([]byte{0x80}, 255), 0x17)} {
			t.Run(fmt.Sprintf("v6=%v/n=%d", v6, len(pattern)), func(t *testing.T) {
				v := extensionVariant(v6)
				v.TCPFlow.PayloadPattern = pattern
				x := setupFlowExtensions(t, v)
				target, _ := parseTCPVariant(v)
				l4 := int(target.l4Off)
				for _, off := range []uint64{0, 1, 2, 255, 256, 511, 1<<32 - 1, 1<<32 + 3, 1<<40 + 17} {
					for _, length := range []uint64{1, 2, 3, 17, 257, 1023} {
						seq := uint32(0xfffffff0)
						f := coreelf.BpfTcpFlow{TemplateId: 0, State: tcpFlowEstablished, SrcPort: 40000, Iss: 100, SndUna: seq, SndNxt: seq, SndMax: seq, RcvNxt: 5001, SndWnd: 65535, Mss: uint16(length), BytesTarget: off + length, BytesAcked: off}
						selectExtensionFlow(t, x, 0, f)
						act, out, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
						if err != nil || act != 3 || len(out) != l4+20+int(length) {
							t.Fatalf("off=%d len=%d: %d/%d %v", off, length, act, len(out), err)
						}
						for i, b := range out[l4+20:] {
							if b != pattern[(off+uint64(i))%uint64(len(pattern))] {
								t.Fatalf("off=%d len=%d byte %d=%x", off, length, i, b)
							}
						}
						if !checksumValid(pseudoHeaderAddrSum(target.srcIP, target.dstIP) + 6 + uint32(20+length) + checksumSum(out[l4:])) {
							t.Fatalf("checksum off=%d len=%d", off, length)
						}
						// Fast retransmit reproduces bytes even across seq wrap.
						f.SndMax = seq + uint32(length)
						f.RtxPending = 1
						selectExtensionFlow(t, x, 0, f)
						act, rtx, err := x.bpfobjs.XdpTxTcpMixed.Test(out)
						if err != nil || act != 3 || !bytes.Equal(out[l4+20:], rtx[l4+20:]) {
							t.Fatalf("retransmit off=%d: %d %v", off, act, err)
						}
					}
				}
			})
		}
	}
}

func TestTCPFlowParamValidation(t *testing.T) {
	valid := guest.VariableParams{ByteStart: 26, ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0xc0000201, End: 0xc0000202}, PatternType: guest.ValuePatternTypeSequential}
	for name, mutate := range map[string]func(*guest.PacketVariant){
		"length":       func(v *guest.PacketVariant) { v.Params[0].ByteStart = guest.ByteStartPacketLength },
		"destination":  func(v *guest.PacketVariant) { v.Params[0].ByteStart = 30 },
		"port":         func(v *guest.PacketVariant) { v.Params[0].ByteStart = 34 },
		"structure":    func(v *guest.PacketVariant) { v.Params[0].ByteStart = 14 },
		"overflow":     func(v *guest.PacketVariant) { v.Params[0].ByteSize = 1 },
		"range":        func(v *guest.PacketVariant) { v.Params[0].ByteRange.End = 0 },
		"pattern":      func(v *guest.PacketVariant) { v.Params[0].PatternType = "typo" },
		"overlap":      func(v *guest.PacketVariant) { v.Params = append(v.Params, v.Params[0]) },
		"missing-base": func(v *guest.PacketVariant) { v.Base = guest.BasePacket{} },
	} {
		t.Run(name, func(t *testing.T) {
			v := extensionVariant(false)
			v.Params = []guest.VariableParams{valid}
			mutate(&v)
			if validateTCPFlowParams(v) == nil {
				t.Fatal("accepted invalid flow params")
			}
		})
	}
	v := extensionVariant(false)
	v.Params = []guest.VariableParams{valid}
	if err := validateTCPFlowParams(v); err != nil {
		t.Fatal(err)
	}
	state := newVariantState(v.Params)
	for _, want := range []uint32{0xc0000201, 0xc0000202, 0xc0000201} {
		next, err := nextTCPFlowVariant(v, state)
		if err != nil || binary.BigEndian.Uint32(next.Base.Data[26:]) != want {
			t.Fatal(next, err)
		}
	}
	if _, err := tcpPayload(make([]byte, 257)); err == nil {
		t.Fatal("accepted oversized pattern")
	}
	for _, syn := range []bool{false, true} {
		if _, err := tcpFlowOptions(&guest.TCPFlowVariant{Timestamps: true, SynOptions: bytes.Repeat([]byte{1}, 21), DataOptions: bytes.Repeat([]byte{1}, 29)}, syn); err == nil {
			t.Fatal("accepted oversized timestamp options")
		}
	}
}

func TestTCPFlowPayloadEncapBPF(t *testing.T) {
	variants := []guest.PacketVariant{tcpTestTunnel("vxlan", false, false, "lco"), tcpTestTunnel("geneve", true, true, "lco"), tcpOtherTunnel("nested"), tcpMaxRawGeneveTemplate()}
	for i := range variants {
		variants[i].TCPFlow.Timestamps = true
		variants[i].TCPFlow.PayloadPattern = []byte{0x12, 0x34, 0xfe}
	}
	x := setupFlowExtensions(t, variants...)
	for i, v := range variants {
		var tmpl coreelf.BpfTcpTemplate
		if err := x.bpfobjs.TcpTemplateMap.Lookup(uint32(i), &tmpl); err != nil {
			t.Fatal(err)
		}
		for _, shared := range []uint8{0, 1} {
			tmpl.Cfg.IpIdShared = shared
			if err := x.bpfobjs.TcpTemplateMap.Put(uint32(i), tmpl); err != nil {
				t.Fatal(err)
			}
			f := lookupExtensionFlow(t, x, uint32(i))
			f.State = tcpFlowEstablished
			f.SndUna = 0xfffffff0
			f.SndNxt = f.SndUna + 7
			f.SndMax = f.SndNxt + 33
			f.BytesAcked = 1<<32 + 17
			f.BytesTarget = f.BytesAcked + 40
			f.SndWnd = 65535
			f.Mss = 33
			f.TsEnabled = 1
			f.TsRecent = 7
			var now unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
				t.Fatal(err)
			}
			f.LastAckNs = uint64(now.Nano())
			f.LastSendNs = f.LastAckNs
			// Give the synthetic established flow a valid timestamp clock.
			f.TsClock = uint32(now.Nano() / 1000000)
			selectExtensionFlow(t, x, uint32(i), f)
			action, out, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
			if err != nil || action != 3 {
				t.Fatal("encap extensions", action, err)
			}
			verifyTCPEncapFrame(t, out, tmpl)
			off := int(tmpl.Cfg.L4Off) + 20 + int(tmpl.DataLen) + 12
			for k, b := range out[off:] {
				if b != v.TCPFlow.PayloadPattern[(f.BytesAcked+7+uint64(k))%3] {
					t.Fatal("GBN payload offset")
				}
			}
			if len(out[off:]) != 33 {
				t.Fatal("short GBN length")
			}
			// The rest of go-back-N and an RTO must use the same absolute stream.
			f.SndUna = f.SndNxt
			f.BytesAcked += 7
			f.SndNxt = f.SndMax
			f.LastAckNs = 1
			f.LastSendNs = 1
			selectExtensionFlow(t, x, uint32(i), f)
			action, rtx, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
			if err != nil || action != 3 || !bytes.Equal(out[off:], rtx[off:]) {
				t.Fatal("RTO payload mismatch", action, err)
			}
			verifyTCPEncapFrame(t, rtx, tmpl)
			// A bare timestamped SYN-ACK must produce the configured tunnel
			// envelope, including correct LCO and the captured IPv4 ID.
			handshake := coreelf.BpfTcpFlow{TemplateId: uint32(i), State: tcpFlowSynSent, SrcPort: uint16(40000 + i), Iss: 100, SndUna: 100, SndNxt: 101, SndMax: 101, TsClock: uint32(now.Nano() / 1000000), BytesTarget: 100}
			selectExtensionFlow(t, x, uint32(i), handshake)
			input := extensionReply(v, handshake.SrcPort, 5000, 101, 0x12, timestampOption(7))
			input = append(input, bytes.Repeat([]byte{0xa5}, 2049-len(input))...)
			action, reply, err := x.bpfobjs.XdpRxTcpMixed.Test(input)
			if err != nil || action != 3 || len(reply) != int(tmpl.Cfg.L4Off)+20+int(tmpl.DataLen)+12 {
				t.Fatal("extended tunnel RX", action, len(reply), err)
			}
			if binary.BigEndian.Uint32(reply[int(tmpl.Cfg.L4Off)+28:]) != 7 {
				t.Fatal("extended tunnel TSecr")
			}
			verifyTCPEncapFrame(t, reply, tmpl)
		}
	}
}

func TestTCPDrainClearsTimestampState(t *testing.T) {
	cpu := pinMixedTestCPU(t)
	timestamped, plain := extensionVariant(false), extensionVariant(false)
	timestamped.TCPFlow.Timestamps = true
	plain.TCPFlow.PayloadPattern = []byte{0x12, 0x34, 0xfe}
	x := setupFlowExtensions(t, timestamped, plain)
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 1 }); err != nil {
		t.Fatal(err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	flows := []coreelf.BpfTcpFlow{
		{TemplateId: 0, State: tcpFlowFinWait1, SrcPort: 40000, TsEnabled: 1, LastSendNs: uint64(now.Nano())},
		{TemplateId: 1, State: tcpFlowEstablished, SrcPort: 40001, Iss: 100, SndUna: 101, SndNxt: 104, SndMax: 104, RcvNxt: 5001, SndWnd: 65535, Mss: 3, BytesTarget: 3, RtxPending: 1},
	}
	for i, f := range flows {
		if err := x.bpfobjs.TcpFlowMap.Put(uint32(i), f); err != nil {
			t.Fatal(err)
		}
	}
	owners := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
	owners[cpu] = coreelf.BpfTcpCpuState{Count: 2, Stride: 1}
	if err := x.bpfobjs.TcpCpuStateMap.Put(uint32(0), owners); err != nil {
		t.Fatal(err)
	}
	cfg := coreelf.BpfMixedCfg{TotalWeight: 2, Groups: 2, Workers: 1, CountLimited: 1}
	if err := x.bpfobjs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
		t.Fatal(err)
	}
	// No frame budget and no initialized group: drain must use the CPU cursor.
	action, out, err := x.bpfobjs.XdpTxMixed.Test(make([]byte, 2049))
	if err != nil || action != 3 || len(out) != 57 {
		t.Fatalf("drain action=%d len=%d: %v", action, len(out), err)
	}
	if out[46]>>4 != 5 || !bytes.Equal(out[54:], plain.TCPFlow.PayloadPattern) {
		t.Fatalf("stale timestamps or payload: %x", out[34:])
	}
	var tmpl coreelf.BpfTcpTemplate
	if err := x.bpfobjs.TcpTemplateMap.Lookup(uint32(1), &tmpl); err != nil {
		t.Fatal(err)
	}
	verifyTCPEncapFrame(t, out, tmpl)
	if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &owners); err != nil {
		t.Fatal(err)
	}
	if owners[cpu].Cursor != 2 {
		t.Fatalf("drain cursor=%d", owners[cpu].Cursor)
	}
	budgets := make([]coreelf.BpfPktState, len(owners))
	if err := x.bpfobjs.PktStateMap.Lookup(uint32(0), &budgets); err != nil || budgets[cpu].Budget != 0 {
		t.Fatalf("drain budget=%d: %v", budgets[cpu].Budget, err)
	}
}
