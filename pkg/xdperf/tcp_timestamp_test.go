package xdperf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

func extensionReply(v guest.PacketVariant, port uint16, seq, ack uint32, flags byte, opts []byte) []byte {
	target, _ := parseTCPVariant(v)
	b := tcpTestBase(target.ipVersion == 6, 0).Data
	l4 := 34
	if target.ipVersion == 6 {
		l4 = 54
		copy(b[22:38], target.dstIP)
		copy(b[38:54], target.srcIP)
		binary.BigEndian.PutUint16(b[18:], uint16(20+len(opts)))
	} else {
		copy(b[26:30], target.dstIP)
		copy(b[30:34], target.srcIP)
		binary.BigEndian.PutUint16(b[16:], uint16(40+len(opts)))
	}
	binary.BigEndian.PutUint16(b[l4:], target.dstPort)
	binary.BigEndian.PutUint16(b[l4+2:], port)
	binary.BigEndian.PutUint32(b[l4+4:], seq)
	binary.BigEndian.PutUint32(b[l4+8:], ack)
	b[l4+12], b[l4+13] = byte((20+len(opts))/4)<<4, flags
	binary.BigEndian.PutUint16(b[l4+14:], 65535)
	return append(b, opts...)
}

func timestampOption(value uint32) []byte {
	b := []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], value)
	return b
}

func lookupExtensionFlow(t *testing.T, x *Xdperf, idx uint32) coreelf.BpfTcpFlow {
	t.Helper()
	var f coreelf.BpfTcpFlow
	if err := x.bpfobjs.TcpFlowMap.Lookup(idx, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTCPTimestampsBPF(t *testing.T) {
	v := extensionVariant(false)
	v.TCPFlow.Timestamps = true
	// EOL must follow engine-generated timestamps, never hide them.
	v.TCPFlow.SynOptions = []byte{0}
	v.TCPFlow.DataOptions = []byte{0}
	x := setupFlowExtensions(t, v)
	initial := lookupExtensionFlow(t, x, 0)
	initial.Iss = 100
	selectExtensionFlow(t, x, 0, initial)
	action, syn, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || len(syn) != 34+20+24 || syn[54] != 1 || syn[56] != 8 {
		t.Fatalf("SYN %d len=%d %v", action, len(syn), err)
	}
	firstClock := binary.BigEndian.Uint32(syn[58:])
	if binary.BigEndian.Uint32(syn[62:]) != 0 {
		t.Fatal("SYN TSecr")
	}
	// SYN retransmissions carry a clock value at least as recent as the SYN.
	f := lookupExtensionFlow(t, x, 0)
	f.LastSendNs = 1
	selectExtensionFlow(t, x, 0, f)
	action, again, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || int32(binary.BigEndian.Uint32(again[58:])-firstClock) < 0 {
		t.Fatal("SYN retry clock", action, err)
	}
	opts := append(timestampOption(0xfffffff0), 2, 4, 4, 0)
	action, ack, err := x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5000, 101, 0x12, opts))
	if err != nil || action != 3 || len(ack) != 34+20+16 || binary.BigEndian.Uint32(ack[62:]) != 0xfffffff0 {
		t.Fatalf("negotiation %d/%d %v", action, len(ack), err)
	}
	f = lookupExtensionFlow(t, x, 0)
	if f.TsEnabled != 1 || f.Mss != 1008 {
		t.Fatalf("negotiated state %+v", f)
	}
	action, data, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || data[46]>>4 != 9 || binary.BigEndian.Uint32(data[62:]) != 0xfffffff0 {
		t.Fatal("data timestamps", action, err)
	}
	if !checksumValid(checksumSum(data[34:]) + pseudoHeaderAddrSum([]byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}) + 6 + uint32(len(data)-34)) {
		t.Fatal("timestamp checksum")
	}
	// A timestamp crossing 2^32 is newer, and its value is echoed on FIN.
	f = lookupExtensionFlow(t, x, 0)
	last := f.SndMax
	action, _, err = x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5001, last, 0x10, timestampOption(3)))
	if err != nil || action != 1 {
		t.Fatal("wrap ACK", action, err)
	}
	f = lookupExtensionFlow(t, x, 0)
	if f.TsRecent != 3 || f.SndUna != last {
		t.Fatal("wrapped timestamp rejected")
	}
	// Snapshotting before the lock must not move the transmitted clock back.
	closing := f
	closing.BytesTarget = closing.BytesAcked
	closing.TsClock = firstClock + 1000000
	selectExtensionFlow(t, x, 0, closing)
	action, fin, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || fin[47] != 0x11 || len(fin) != 70 || binary.BigEndian.Uint32(fin[58:]) != closing.TsClock || binary.BigEndian.Uint32(fin[62:]) != 3 {
		t.Fatal("FIN timestamps/clock clamp", action, err)
	}
	action, final, err := x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5001, last+1, 0x11, timestampOption(4)))
	if err != nil || action != 3 || final[47] != 0x10 || binary.BigEndian.Uint32(final[62:]) != 4 || lookupExtensionFlow(t, x, 0).State != tcpFlowDone {
		t.Fatal("final ACK timestamps", action, err)
	}
	// Simulate the prior transmitted millisecond just before uint32 wrap.
	// The host's real clock is the post-wrap observation on shorter uptimes.
	if firstClock < 0x7ffff000 {
		closing.TsClock = 0xfffffff0
		selectExtensionFlow(t, x, 0, closing)
		action, wrapped, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
		clock := binary.BigEndian.Uint32(wrapped[58:])
		if err != nil || action != 3 || clock >= closing.TsClock || int32(clock-closing.TsClock) < 0 {
			t.Fatal("local timestamp wrap", action, clock, err)
		}
	}
	// PAWS and missing timestamps must not advance the ACK or window.
	f.SndMax = last + 10
	selectExtensionFlow(t, x, 0, f)
	for _, bad := range [][]byte{timestampOption(0xfffffff0), nil, append(timestampOption(5), timestampOption(6)...), {8, 2, 0, 0}} {
		_, _, err = x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5001, last+10, 0x10, bad))
		if err != nil {
			t.Fatal(err)
		}
		got := lookupExtensionFlow(t, x, 0)
		if got.SndUna != last || got.TsRecent != 3 {
			t.Fatal("bad timestamp changed flow")
		}
	}
	// A timestamp-less RST remains valid after negotiation.
	action, _, err = x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5001, last, 0x04, nil))
	if err != nil || action != 1 || lookupExtensionFlow(t, x, 0).State != tcpFlowFailed {
		t.Fatal("timestamp-less RST", action, err)
	}
	// A peer declining timestamps gets no timestamps on ACK/data/FIN.
	initial = coreelf.BpfTcpFlow{State: tcpFlowClosed, SrcPort: 40000, Iss: 100, BytesTarget: 1}
	selectExtensionFlow(t, x, 0, initial)
	if _, _, err = x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049)); err != nil {
		t.Fatal(err)
	}
	action, ack, err = x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5000, 101, 0x12, nil))
	if err != nil || action != 3 || len(ack) != 34+24 || lookupExtensionFlow(t, x, 0).TsEnabled != 0 {
		t.Fatal("declined timestamps", action, len(ack), err)
	}
	action, plain, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || plain[46]>>4 != 6 || len(plain) != 59 {
		t.Fatal("declined data", action, err)
	}
	if _, _, err = x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, 40000, 5001, 102, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	action, plain, err = x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil || action != 3 || plain[47] != 0x11 || len(plain) != 58 {
		t.Fatal("declined FIN", action, err)
	}
}

func TestTCPFlowParamsBPF(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		v := extensionVariant(v6)
		start := uint64(29)
		if v6 {
			start = 37
		}
		v.Params = []guest.VariableParams{{ByteStart: start, ByteSize: 1, ByteRange: guest.TemplateRange{Start: 11, End: 12}, PatternType: guest.ValuePatternTypeSequential}}
		v.TCPFlow.Flows = append(v.TCPFlow.Flows, guest.TCPFlow{Bytes: "20000"})
		v.TCPFlow.Timestamps = true
		v.TCPFlow.PayloadPattern = []byte("abc")
		x := setupFlowExtensions(t, v)
		for i := uint32(0); i < 2; i++ {
			f := lookupExtensionFlow(t, x, i)
			if f.TemplateId != 16+i {
				t.Fatal("wrong expanded template", f.TemplateId)
			}
			f.Iss = 100
			selectExtensionFlow(t, x, i, f)
			action, syn, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
			if err != nil || action != 3 || syn[start] != byte(11+i) {
				t.Fatal("flow source IP", action, err)
			}
			wrong := extensionReply(v, uint16(40000+i), 5000, 101, 0x12, timestampOption(7))
			action, _, err = x.bpfobjs.XdpRxTcpMixed.Test(wrong)
			if err != nil || action != 2 {
				t.Fatal("accepted wrong flow IP", action, err)
			}
			dst := 33
			if v6 {
				dst = 53
			}
			wrong = extensionReply(v, uint16(40000+i), 5000, 101, 0x12, timestampOption(7))
			wrong[dst] = byte(11 + i)
			action, ack, err := x.bpfobjs.XdpRxTcpMixed.Test(wrong)
			if err != nil || action != 3 || ack[start] != byte(11+i) {
				t.Fatal("flow RX", action, err)
			}
		}
		if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 1 }); err != nil {
			t.Fatal(err)
		}
		for _, id := range []uint32{16, 17} {
			var tm coreelf.BpfTcpTemplate
			if err := x.bpfobjs.TcpTemplateMap.Lookup(id, &tm); err != nil || tm.Cfg.Drain != 1 {
				t.Fatal("expanded template drain", err)
			}
		}
	}
}
