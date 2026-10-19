package xdperf

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	objs, spec, err := coreelf.ReadBaseCollectionWithSizes(map[string]any{"swap_resp": uint32(0)}, map[string]uint32{"diff_map": 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { objs.Close() })
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfobjs: objs, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants[:1], variants...)
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if err := coreelf.LoadMixedProgramsWithFeatures(objs, spec, x.mixed.features); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load extensions: %+v", ve)
		}
		t.Fatal(err)
	}
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
	states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
	for i := range states {
		states[i].SelectedFlow = idx
	}
	if err := x.bpfobjs.MixedStateMap.Put(uint32(0), states); err != nil {
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
	}
}
