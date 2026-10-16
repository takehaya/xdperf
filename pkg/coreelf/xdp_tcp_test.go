package coreelf

// Data-plane tests for the TCP programs (src/xdp_tcp.h, src/xdp_tcp_server.h),
// run through BPF_PROG_TEST_RUN in non-live mode: the program's action is the
// return value and the rewritten frame comes back in DataOut. Checksums are
// verified independently of the BPF code (tcpChecksumOK / ipv4ChecksumOK).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	xdpAborted = 0
	xdpDrop    = 1
	xdpPass    = 2

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10

	// mirror enum tcp_flow_state / tcp_srv_state
	tfClosed      = 0
	tfSynSent     = 1
	tfEstablished = 2
	tfFinWait1    = 3
	tfFinWait2    = 4
	tfDone        = 5
	tfFailed      = 6

	tsSynRcvd     = 1
	tsEstablished = 2
	tsLastAck     = 3

	testDstPort  = 5201
	testPortBase = 10000
	testVlanID   = 110
)

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a} // XDP side
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b} // peer
	ipA4 = net.IP{192, 168, 110, 1}
	ipB4 = net.IP{192, 168, 110, 2}
	ipA6 = net.ParseIP("fd00:110::1")
	ipB6 = net.ParseIP("fd00:110::2")
)

func loadTCPObjs(t *testing.T) *BpfObjects {
	t.Helper()
	objs, _, err := ReadCollectionWithSizes(defaultConsts(), map[string]uint32{"diff_map": 1, "tcp_srv_flow_map": 1024})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("ReadCollection failed: %+v", ve)
		}
		t.Fatalf("ReadCollection failed: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return objs
}

// seg describes a TCP segment to build. The frame goes from "src" to "dst".
type seg struct {
	v6         bool
	vlan       uint16 // 0 = untagged
	srcMAC     net.HardwareAddr
	dstMAC     net.HardwareAddr
	src, dst   net.IP
	sport      uint16
	dport      uint16
	seq, ack   uint32
	flags      uint8
	win        uint16
	payloadLen int
	opts       []layers.TCPOption
	udp        bool
}

func buildSeg(t *testing.T, s seg) []byte {
	t.Helper()
	if s.srcMAC == nil {
		s.srcMAC, s.dstMAC = macB, macA
	}
	eth := &layers.Ethernet{SrcMAC: s.srcMAC, DstMAC: s.dstMAC}
	var ls []gopacket.SerializableLayer
	ls = append(ls, eth)
	l3type := layers.EthernetTypeIPv4
	if s.v6 {
		l3type = layers.EthernetTypeIPv6
	}
	if s.vlan != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		ls = append(ls, &layers.Dot1Q{VLANIdentifier: s.vlan, Type: l3type})
	} else {
		eth.EthernetType = l3type
	}
	proto := layers.IPProtocolTCP
	if s.udp {
		proto = layers.IPProtocolUDP
	}
	var nl gopacket.NetworkLayer
	if s.v6 {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto, SrcIP: s.src, DstIP: s.dst}
		ls = append(ls, ip)
		nl = ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: s.src.To4(), DstIP: s.dst.To4()}
		ls = append(ls, ip)
		nl = ip
	}
	if s.udp {
		u := &layers.UDP{SrcPort: layers.UDPPort(s.sport), DstPort: layers.UDPPort(s.dport)}
		_ = u.SetNetworkLayerForChecksum(nl)
		ls = append(ls, u)
	} else {
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(s.sport), DstPort: layers.TCPPort(s.dport),
			Seq: s.seq, Ack: s.ack, Window: s.win, Options: s.opts,
			FIN: s.flags&tcpFIN != 0, SYN: s.flags&tcpSYN != 0, RST: s.flags&tcpRST != 0,
			PSH: s.flags&tcpPSH != 0, ACK: s.flags&tcpACK != 0,
		}
		_ = tcp.SetNetworkLayerForChecksum(nl)
		ls = append(ls, tcp)
	}
	ls = append(ls, gopacket.Payload(make([]byte, s.payloadLen)))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// fromPeer builds a segment the peer (B, port 5201) sends to flow idx on the XDP side.
func fromPeer(v6 bool, idx uint16, seq, ack uint32, flags uint8) seg {
	s := seg{v6: v6, src: ipB4, dst: ipA4, sport: testDstPort, dport: testPortBase + idx, seq: seq, ack: ack, flags: flags, win: 65535}
	if v6 {
		s.src, s.dst = ipB6, ipA6
	}
	return s
}

// monoNow is bpf_ktime_get_ns() as seen from user space.
func monoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

func runProg(t *testing.T, prog *ebpf.Program, in []byte) (uint32, []byte) {
	t.Helper()
	opts := &ebpf.RunOptions{
		Data:    in,
		DataOut: make([]byte, len(in)+4096),
		Context: XdpMd{DataEnd: uint32(len(in))},
	}
	ret, err := prog.Run(opts)
	if err != nil {
		t.Fatalf("prog.Run: %v", err)
	}
	return ret, opts.DataOut
}

type decoded struct {
	eth  *layers.Ethernet
	vlan *layers.Dot1Q
	ip4  *layers.IPv4
	ip6  *layers.IPv6
	tcp  *layers.TCP
}

func decode(t *testing.T, frame []byte) decoded {
	t.Helper()
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := p.ErrorLayer(); el != nil {
		t.Fatalf("decode: %v", el.Error())
	}
	var d decoded
	d.eth, _ = p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	d.vlan, _ = p.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	d.ip4, _ = p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	d.ip6, _ = p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	d.tcp, _ = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if d.tcp == nil {
		t.Fatal("no TCP layer in output")
	}
	if d.ip4 != nil && !ipv4ChecksumOK(d.ip4.Contents) {
		t.Fatal("bad IPv4 header checksum")
	}
	if !tcpChecksumOK(d) {
		t.Fatal("bad TCP checksum")
	}
	return d
}

func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

func ipv4ChecksumOK(hdr []byte) bool { return fold(sum16(hdr)) == 0xffff }

func tcpChecksumOK(d decoded) bool {
	segment := append(append([]byte(nil), d.tcp.Contents...), d.tcp.Payload...)
	var s uint32
	if d.ip4 != nil {
		s = sum16(d.ip4.SrcIP.To4()) + sum16(d.ip4.DstIP.To4())
	} else {
		s = sum16(d.ip6.SrcIP) + sum16(d.ip6.DstIP)
	}
	s += uint32(layers.IPProtocolTCP) + uint32(len(segment)) + sum16(segment)
	return fold(s) == 0xffff
}

func tcpFlags(tcp *layers.TCP) uint8 {
	var f uint8
	if tcp.FIN {
		f |= tcpFIN
	}
	if tcp.SYN {
		f |= tcpSYN
	}
	if tcp.RST {
		f |= tcpRST
	}
	if tcp.PSH {
		f |= tcpPSH
	}
	if tcp.ACK {
		f |= tcpACK
	}
	return f
}

func ipWords(ip net.IP) [4]uint32 {
	var w [4]uint32
	if ip4 := ip.To4(); ip4 != nil {
		w[0] = binary.NativeEndian.Uint32(ip4)
		return w
	}
	for i := 0; i < 4; i++ {
		w[i] = binary.NativeEndian.Uint32(ip[i*4:])
	}
	return w
}

// ---------------------------------------------------------------------------
// client (xdp_tx_tcp / xdp_rx_tcp)
// ---------------------------------------------------------------------------

type clientOpts struct {
	v6       bool
	vlan     uint16
	flows    uint32
	mss      uint16
	window   uint32
	rtoNs    uint64
	drain    bool
	abort    bool
	maxData  uint8
	bytesPer uint64
}

// clientTemplate is the L2+L3 header the TX program copies into every frame
// and the full template frame (hdr + mss zero bytes) used as TX input.
func clientTemplate(t *testing.T, o clientOpts) (cfg BpfTcpCfg, frame []byte) {
	t.Helper()
	s := seg{v6: o.v6, vlan: o.vlan, srcMAC: macA, dstMAC: macB, src: ipA4, dst: ipB4,
		sport: testPortBase, dport: testDstPort, flags: tcpACK, win: 65535, payloadLen: int(o.mss)}
	if o.v6 {
		s.src, s.dst = ipA6, ipB6
	}
	frame = buildSeg(t, s)
	l3 := uint16(14)
	if o.vlan != 0 {
		l3 = 18
	}
	l4 := l3 + 20
	ipv := uint8(4)
	src, dst := ipA4, ipB4
	if o.v6 {
		l4 = l3 + 40
		ipv = 6
		src, dst = ipA6, ipB6
	}
	var ps uint32
	if o.v6 {
		ps = sum16(src) + sum16(dst)
	} else {
		ps = sum16(src.To4()) + sum16(dst.To4())
	}
	cfg = BpfTcpCfg{
		FlowCount: o.flows, WindowSegs: o.window, Mss: o.mss, PortBase: testPortBase, DstPort: testDstPort,
		HdrLen: l4 + 20, L3Off: l3, L4Off: l4, VlanId: o.vlan, VlanPcp: 3, IpVersion: ipv,
		MaxSynRetries: 6, MaxFinRetries: 6, MaxDataRetries: o.maxData,
		PseudoSum: ps, SrcIp: ipWords(src), DstIp: ipWords(dst), BytesPerFlow: o.bytesPer, RtoNs: o.rtoNs,
	}
	if o.drain {
		cfg.Drain = 1
	}
	if o.abort {
		cfg.Abort = 1
	}
	copy(cfg.HdrTmpl[:], frame[:l4])
	return cfg, frame
}

func setupClient(t *testing.T, objs *BpfObjects, o clientOpts, flows ...BpfTcpFlow) []byte {
	t.Helper()
	if o.flows == 0 {
		o.flows = uint32(len(flows))
	}
	if o.mss == 0 {
		o.mss = 1000
	}
	if o.window == 0 {
		o.window = 32
	}
	if o.rtoNs == 0 {
		// ~2.3 years, longer than any uptime (LastSendNs = 0 means "sent at
		// boot"); still fits in 64 bits after the largest backoff shift (<< 6)
		o.rtoNs = 1 << 56 // no RTO unless a test asks for one
	}
	if o.maxData == 0 {
		o.maxData = 8
	}
	cfg, frame := clientTemplate(t, o)
	zero := uint32(0)
	if err := objs.TcpCfgMap.Put(&zero, &cfg); err != nil {
		t.Fatal(err)
	}
	for i := range flows {
		k := uint32(i)
		flows[i].SrcPort = testPortBase + uint16(i)
		if err := objs.TcpFlowMap.Put(&k, &flows[i]); err != nil {
			t.Fatal(err)
		}
	}
	// Every CPU drives flows 0..n-1, so the test does not depend on which
	// CPU BPF_PROG_RUN executes on.
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	states := make([]BpfTcpCpuState, n)
	for i := range states {
		states[i] = BpfTcpCpuState{First: 0, Stride: 1, Count: uint32(len(flows))}
	}
	if err := objs.TcpCpuStateMap.Put(&zero, states); err != nil {
		t.Fatal(err)
	}
	return frame
}

func getFlow(t *testing.T, objs *BpfObjects, idx uint32) BpfTcpFlow {
	t.Helper()
	var f BpfTcpFlow
	if err := objs.TcpFlowMap.Lookup(&idx, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func clientStats(t *testing.T, objs *BpfObjects) BpfTcpStats {
	t.Helper()
	n, _ := ebpf.PossibleCPU()
	recs := make([]BpfTcpStats, n)
	zero := uint32(0)
	if err := objs.TcpStatsMap.Lookup(&zero, &recs); err != nil {
		t.Fatal(err)
	}
	var s BpfTcpStats
	for _, r := range recs {
		s.RstSent += r.RstSent
		s.FailedEst += r.FailedEst
		s.Failed += r.Failed
		s.RtxSegs += r.RtxSegs
		s.RtxGiveups += r.RtxGiveups
		s.Aborted += r.Aborted
		s.AckProbes += r.AckProbes
		s.Established += r.Established
		s.BytesAcked += r.BytesAcked
	}
	return s
}

func synSent(iss uint32) BpfTcpFlow {
	return BpfTcpFlow{State: tfSynSent, Iss: iss, SndUna: iss, SndNxt: iss + 1, SndMax: iss + 1}
}

func established(iss uint32) BpfTcpFlow {
	return BpfTcpFlow{State: tfEstablished, Iss: iss, SndUna: iss + 1, SndNxt: iss + 1, SndMax: iss + 1,
		RcvNxt: 5001, SndWnd: 1 << 30, Mss: 1000}
}

func TestTcpRxSynAckEstablishes(t *testing.T) {
	for _, tc := range []struct {
		name string
		v6   bool
		vlan uint16
	}{{"v4", false, 0}, {"v6", true, 0}, {"v4 vlan stripped", false, testVlanID}, {"v6 vlan stripped", true, testVlanID}} {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadTCPObjs(t)
			setupClient(t, objs, clientOpts{v6: tc.v6, vlan: tc.vlan}, synSent(1000))
			s := fromPeer(tc.v6, 0, 5000, 1001, tcpSYN|tcpACK)
			s.win = 1000
			s.opts = []layers.TCPOption{
				{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x02, 0x00}}, // 512
				{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
				{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
			}
			// rx-vlan-offload: the frame arrives untagged even when a VLAN is configured
			ret, out := runProg(t, objs.XdpRxTcp, buildSeg(t, s))
			if ret != xdpTx {
				t.Fatalf("ret = %d, want XDP_TX", ret)
			}
			d := decode(t, out)
			if tcpFlags(d.tcp) != tcpACK || d.tcp.Seq != 1001 || d.tcp.Ack != 5001 {
				t.Fatalf("reply flags=%#x seq=%d ack=%d", tcpFlags(d.tcp), d.tcp.Seq, d.tcp.Ack)
			}
			if d.tcp.SrcPort != testPortBase || d.tcp.DstPort != testDstPort {
				t.Fatalf("ports not swapped: %d -> %d", d.tcp.SrcPort, d.tcp.DstPort)
			}
			if !bytes.Equal(d.eth.SrcMAC, macA) || !bytes.Equal(d.eth.DstMAC, macB) {
				t.Fatalf("MACs not swapped: %s -> %s", d.eth.SrcMAC, d.eth.DstMAC)
			}
			if tc.vlan != 0 {
				if d.vlan == nil || d.vlan.VLANIdentifier != tc.vlan || d.vlan.Priority != 3 {
					t.Fatalf("VLAN tag not pushed back: %+v", d.vlan)
				}
			} else if d.vlan != nil {
				t.Fatal("unexpected VLAN tag")
			}
			f := getFlow(t, objs, 0)
			// RFC 7323: the SYN-ACK window is not scaled
			if f.State != tfEstablished || f.Mss != 512 || f.Wscale != 7 || f.SndWnd != 1000 || f.RcvNxt != 5001 {
				t.Fatalf("flow = %+v", f)
			}
		})
	}
}

func TestTcpRxDropsBadLength(t *testing.T) {
	objs := loadTCPObjs(t)
	setupClient(t, objs, clientOpts{}, synSent(1000))
	// SYN-ACK whose IP header claims 1000 bytes that are not in the frame.
	frame := buildSeg(t, fromPeer(false, 0, 5000, 1001, tcpSYN|tcpACK))
	binary.BigEndian.PutUint16(frame[14+2:], 20+20+1000)
	if ret, _ := runProg(t, objs.XdpRxTcp, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want XDP_DROP", ret)
	}
	if f := getFlow(t, objs, 0); f.State != tfSynSent {
		t.Fatalf("flow changed by a truncated segment: %+v", f)
	}
}

func TestTcpRxSynSentStaleAckIsReset(t *testing.T) {
	objs := loadTCPObjs(t)
	setupClient(t, objs, clientOpts{}, synSent(1000))
	// The peer still holds a connection from an earlier run: challenge ACK.
	in := buildSeg(t, fromPeer(false, 0, 7777, 424242, tcpACK))
	ret, out := runProg(t, objs.XdpRxTcp, in)
	if ret != xdpTx {
		t.Fatalf("ret = %d, want XDP_TX (RST)", ret)
	}
	d := decode(t, out)
	if tcpFlags(d.tcp) != tcpRST || d.tcp.Seq != 424242 {
		t.Fatalf("want <SEQ=SEG.ACK><CTL=RST>, got flags=%#x seq=%d", tcpFlags(d.tcp), d.tcp.Seq)
	}
	if f := getFlow(t, objs, 0); f.State != tfSynSent || f.SynRst != 1 {
		t.Fatalf("flow = state %d syn_rst %d, want SYN_SENT with immediate resend", f.State, f.SynRst)
	}
	// The immediate resend is used once only.
	f := getFlow(t, objs, 0)
	f.SynRst = 2
	k := uint32(0)
	if err := objs.TcpFlowMap.Put(&k, &f); err != nil {
		t.Fatal(err)
	}
	runProg(t, objs.XdpRxTcp, in)
	if f := getFlow(t, objs, 0); f.SynRst != 2 {
		t.Fatalf("syn_rst = %d, want 2 (no second immediate resend)", f.SynRst)
	}
}

func TestTcpRxSynSentRstAcceptance(t *testing.T) {
	objs := loadTCPObjs(t)
	setupClient(t, objs, clientOpts{}, synSent(1000))
	// A RST that does not ack our SYN (leftover of an earlier run) is ignored.
	if ret, _ := runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 0, 999, tcpRST|tcpACK))); ret != xdpDrop {
		t.Fatalf("ret = %d, want XDP_DROP", ret)
	}
	if f := getFlow(t, objs, 0); f.State != tfSynSent {
		t.Fatalf("state = %d, want SYN_SENT", f.State)
	}
	runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 0, 1001, tcpRST|tcpACK)))
	if f := getFlow(t, objs, 0); f.State != tfFailed {
		t.Fatalf("state = %d, want FAILED", f.State)
	}
}

func TestTcpRxAcceptsAckAboveRewoundSndNxt(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.SndUna = 1
	f.SndNxt = 1 + 1000    // go-back-N rewound after an RTO
	f.SndMax = 1 + 10*1000 // highest seq sent
	f.RtxPending = 1
	f.DupAcks = 3
	setupClient(t, objs, clientOpts{}, f)

	s := fromPeer(false, 0, 5001, 1+5*1000, tcpACK)
	if ret, _ := runProg(t, objs.XdpRxTcp, buildSeg(t, s)); ret != xdpDrop {
		t.Fatalf("pure ACK must not be answered, ret = %d", ret)
	}
	got := getFlow(t, objs, 0)
	if got.SndUna != 5001 || got.SndNxt != 5001 || got.BytesAcked != 5000 || got.RtxPending != 0 || got.DupAcks != 0 {
		t.Fatalf("flow = una %d nxt %d acked %d rtx_pending %d dup %d", got.SndUna, got.SndNxt, got.BytesAcked, got.RtxPending, got.DupAcks)
	}
	// Beyond snd_max: ignored.
	runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 5001, 1+11*1000, tcpACK)))
	if got := getFlow(t, objs, 0); got.SndUna != 5001 {
		t.Fatalf("ACK beyond snd_max accepted: una %d", got.SndUna)
	}
}

func TestTcpRxDupAckIgnoresWindowUpdates(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.SndNxt, f.SndMax = 1+4000, 1+4000
	f.SndWnd = 65535
	setupClient(t, objs, clientOpts{}, f)
	for i := 0; i < 3; i++ {
		s := fromPeer(false, 0, 5001, 1, tcpACK)
		s.win = uint16(60000 + i) // window update: not a duplicate ACK
		runProg(t, objs.XdpRxTcp, buildSeg(t, s))
	}
	if got := getFlow(t, objs, 0); got.DupAcks != 0 || got.RtxPending != 0 {
		t.Fatalf("window updates counted as dup ACKs: %d", got.DupAcks)
	}
	for i := 0; i < 3; i++ {
		s := fromPeer(false, 0, 5001, 1, tcpACK)
		s.win = 60002
		runProg(t, objs.XdpRxTcp, buildSeg(t, s))
	}
	if got := getFlow(t, objs, 0); got.RtxPending != 1 {
		t.Fatalf("3 dup ACKs did not trigger fast retransmit (dup=%d)", got.DupAcks)
	}
}

func TestTcpRxFinMustBeInSequence(t *testing.T) {
	objs := loadTCPObjs(t)
	setupClient(t, objs, clientOpts{}, established(0))
	ret, out := runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 6000, 1, tcpFIN|tcpACK)))
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); d.tcp.Ack != 5001 {
		t.Fatalf("out-of-sequence FIN acked: ack %d", d.tcp.Ack)
	}
	if got := getFlow(t, objs, 0); got.PeerFin != 0 || got.RcvNxt != 5001 {
		t.Fatalf("out-of-sequence FIN accepted: %+v", got)
	}
}

func TestTcpRxFailedFlowIsReset(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.State = tfFailed
	setupClient(t, objs, clientOpts{}, f)
	ret, out := runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 5001, 777, tcpACK)))
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpRST || d.tcp.Seq != 777 {
		t.Fatalf("got flags %#x seq %d", tcpFlags(d.tcp), d.tcp.Seq)
	}
}

func TestTcpRxPassesForeignTraffic(t *testing.T) {
	ip6ext := func(t *testing.T) []byte {
		b := buildSeg(t, fromPeer(true, 0, 1, 1, tcpACK))
		b[14+6] = 0 // next header: hop-by-hop instead of TCP
		return b
	}
	cases := []struct {
		name string
		v6   bool
		vlan uint16
		pkt  func(t *testing.T) []byte
	}{
		{"other source port", false, 0, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 1, 1, tcpACK)
			s.sport = 22
			return buildSeg(t, s)
		}},
		{"port below range", false, 0, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 1, 1, tcpACK)
			s.dport = testPortBase - 1
			return buildSeg(t, s)
		}},
		{"port above range", false, 0, func(t *testing.T) []byte { return buildSeg(t, fromPeer(false, 1, 1, 1, tcpACK)) }},
		{"other peer address", false, 0, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 1, 1, tcpACK)
			s.src = net.IP{192, 168, 110, 99}
			return buildSeg(t, s)
		}},
		{"udp", false, 0, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 0, 0, 0)
			s.udp = true
			return buildSeg(t, s)
		}},
		{"ipv4 while ipv6 configured", true, 0, func(t *testing.T) []byte { return buildSeg(t, fromPeer(false, 0, 1, 1, tcpACK)) }},
		{"ipv6 extension header", true, 0, ip6ext},
		{"other vlan", false, testVlanID, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 1, 1, tcpACK)
			s.vlan = testVlanID + 1
			return buildSeg(t, s)
		}},
		{"tagged while untagged configured", false, 0, func(t *testing.T) []byte {
			s := fromPeer(false, 0, 1, 1, tcpACK)
			s.vlan = testVlanID
			return buildSeg(t, s)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadTCPObjs(t)
			setupClient(t, objs, clientOpts{v6: tc.v6, vlan: tc.vlan}, established(0))
			in := tc.pkt(t)
			ret, out := runProg(t, objs.XdpRxTcp, in)
			if ret != xdpPass {
				t.Fatalf("ret = %d, want XDP_PASS", ret)
			}
			if !bytes.Equal(out[:len(in)], in) {
				t.Fatal("passed frame was modified")
			}
		})
	}
}

// txOnce runs xdp_tx_tcp once (non-live) on the template frame.
func txOnce(t *testing.T, objs *BpfObjects, frame []byte) (uint32, []byte) {
	t.Helper()
	return runProg(t, objs.XdpTxTcp, frame)
}

func TestTcpTxFinAfterMoreThan4GiB(t *testing.T) {
	objs := loadTCPObjs(t)
	const target = 5 << 30
	f := established(0xFFFFFF00)
	f.BytesTarget, f.BytesAcked = target, target
	end := f.Iss + 1 + uint32(target%(1<<32))
	f.SndUna, f.SndNxt, f.SndMax = end, end, end
	frame := setupClient(t, objs, clientOpts{}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	d := decode(t, out)
	if tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Seq != end || len(d.tcp.Payload) != 0 {
		t.Fatalf("want FIN at %d, got flags %#x seq %d len %d", end, tcpFlags(d.tcp), d.tcp.Seq, len(d.tcp.Payload))
	}
	if got := getFlow(t, objs, 0); got.State != tfFinWait1 || got.SndMax != end+1 {
		t.Fatalf("flow = state %d snd_max %d", got.State, got.SndMax)
	}
}

func TestTcpTxUsesPeerMSSAndPushesWhenWindowFull(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.Mss = 500 // peer advertised less than our 1000
	frame := setupClient(t, objs, clientOpts{window: 3}, f)
	for i := 0; i < 3; i++ {
		ret, out := txOnce(t, objs, frame)
		if ret != xdpTx {
			t.Fatalf("segment %d: ret = %d", i, ret)
		}
		d := decode(t, out)
		if len(d.tcp.Payload) != 500 {
			t.Fatalf("segment %d: payload %d, want peer MSS 500", i, len(d.tcp.Payload))
		}
		wantPSH := i == 2 // the third segment fills the 3-segment window
		if d.tcp.PSH != wantPSH {
			t.Fatalf("segment %d: PSH = %v, want %v", i, d.tcp.PSH, wantPSH)
		}
	}
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("window full: ret = %d, want XDP_DROP", ret)
	}
}

func TestTcpTxResendsGoBackNRegionWhileDraining(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.SndUna, f.SndNxt, f.SndMax = 1, 1+1000, 1+5000
	frame := setupClient(t, objs, clientOpts{drain: true}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d, want the go-back-N region to be sent while draining", ret)
	}
	if d := decode(t, out); d.tcp.Seq != 1001 || len(d.tcp.Payload) != 1000 {
		t.Fatalf("seq %d len %d", d.tcp.Seq, len(d.tcp.Payload))
	}
	if s := clientStats(t, objs); s.RtxSegs != 1 {
		t.Fatalf("rtx_segs = %d, want 1", s.RtxSegs)
	}
}

func TestTcpTxAbortResets(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.SndUna, f.SndNxt, f.SndMax = 1, 1001, 3001
	frame := setupClient(t, objs, clientOpts{abort: true}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	d := decode(t, out)
	if tcpFlags(d.tcp) != tcpRST|tcpACK || d.tcp.Seq != 3001 || d.tcp.Ack != 5001 {
		t.Fatalf("want RST|ACK seq=snd_max, got flags %#x seq %d ack %d", tcpFlags(d.tcp), d.tcp.Seq, d.tcp.Ack)
	}
	if s := clientStats(t, objs); s.Aborted != 1 || s.FailedEst != 1 || s.RstSent != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTcpTxGivesUpAfterDataRetries(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.SndUna, f.SndNxt, f.SndMax = 1, 1001, 1001
	f.RtxRetries = 2
	frame := setupClient(t, objs, clientOpts{rtoNs: 1000, maxData: 2}, f) // LastSendNs = 0: RTO expired
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); !d.tcp.RST {
		t.Fatalf("want RST after max data retries, got flags %#x", tcpFlags(d.tcp))
	}
	if s := clientStats(t, objs); s.RtxGiveups != 1 {
		t.Fatalf("rtx_giveups = %d", s.RtxGiveups)
	}
}

func TestTcpTxFinWait2Probe(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.State = tfFinWait2
	f.SndUna, f.SndNxt, f.SndMax = 101, 101, 101
	frame := setupClient(t, objs, clientOpts{rtoNs: 1000}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	d := decode(t, out)
	if tcpFlags(d.tcp) != tcpACK || d.tcp.Seq != 101 || d.tcp.Ack != 5001 {
		t.Fatalf("probe flags %#x seq %d ack %d", tcpFlags(d.tcp), d.tcp.Seq, d.tcp.Ack)
	}
	if got := getFlow(t, objs, 0); got.FinRetries != 1 {
		t.Fatalf("fin_retries = %d", got.FinRetries)
	}
}

func TestTcpTxImmediateSynResendAfterStaleReset(t *testing.T) {
	objs := loadTCPObjs(t)
	f := synSent(1000)
	f.SynRst = 1
	f.LastSendNs = monoNow(t) // just sent: the normal backoff would not fire
	frame := setupClient(t, objs, clientOpts{}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d, want an immediate SYN", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpSYN || d.tcp.Seq != 1000 {
		t.Fatalf("flags %#x seq %d", tcpFlags(d.tcp), d.tcp.Seq)
	}
	got := getFlow(t, objs, 0)
	if got.SynRst != 2 || got.SynRetries != 0 {
		t.Fatalf("syn_rst %d syn_retries %d, want 2 / 0 (resend once, no retry consumed)", got.SynRst, got.SynRetries)
	}
	// Used: no second immediate resend.
	got.LastSendNs = monoNow(t)
	k := uint32(0)
	if err := objs.TcpFlowMap.Put(&k, &got); err != nil {
		t.Fatal(err)
	}
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("second immediate resend: ret %d", ret)
	}
}

func TestTcpRxFinWait1Close(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.State = tfFinWait1
	f.SndUna, f.SndNxt, f.SndMax = 1+3000, 1+3001, 1+3001 // FIN at seq 3001
	f.BytesAcked = 3000
	setupClient(t, objs, clientOpts{}, f)
	// ACK of the FIN together with the peer's FIN: DONE, FIN not counted as data.
	ret, out := runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 5001, 1+3001, tcpFIN|tcpACK)))
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpACK || d.tcp.Ack != 5002 || d.tcp.Seq != 1+3001 {
		t.Fatalf("final ACK flags %#x seq %d ack %d", tcpFlags(d.tcp), d.tcp.Seq, d.tcp.Ack)
	}
	got := getFlow(t, objs, 0)
	if got.State != tfDone || got.BytesAcked != 3000 {
		t.Fatalf("state %d bytes_acked %d, want DONE / 3000", got.State, got.BytesAcked)
	}
}

func TestTcpRxEstablishedReAcksRetransmittedSynAck(t *testing.T) {
	objs := loadTCPObjs(t)
	setupClient(t, objs, clientOpts{}, established(1000))
	ret, out := runProg(t, objs.XdpRxTcp, buildSeg(t, fromPeer(false, 0, 5000, 1001, tcpSYN|tcpACK)))
	if ret != xdpTx {
		t.Fatalf("ret = %d, want the handshake ACK again", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpACK || d.tcp.Ack != 5001 {
		t.Fatalf("flags %#x ack %d", tcpFlags(d.tcp), d.tcp.Ack)
	}
}

func TestTcpTxFinWait2TimesOut(t *testing.T) {
	objs := loadTCPObjs(t)
	f := established(0)
	f.State = tfFinWait2
	f.SndUna, f.SndNxt, f.SndMax = 101, 101, 101
	f.FinRetries = 6
	frame := setupClient(t, objs, clientOpts{rtoNs: 1000}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpRST|tcpACK || d.tcp.Seq != 101 {
		t.Fatalf("flags %#x seq %d", tcpFlags(d.tcp), d.tcp.Seq)
	}
	if got := getFlow(t, objs, 0); got.State != tfFailed {
		t.Fatalf("state %d, want FAILED", got.State)
	}
}

// ---------------------------------------------------------------------------
// responder (xdp_rx_tcp_server)
// ---------------------------------------------------------------------------

func setupServer(t *testing.T, objs *BpfObjects, v6 bool, ackEvery uint8, anyAddr bool) {
	t.Helper()
	cfg := BpfTcpSrvCfg{ListenPort: testDstPort, IpVersion: 4, AckEvery: ackEvery, Mss: 1448, ListenIp: ipWords(ipB4)}
	if v6 {
		cfg.IpVersion = 6
		cfg.ListenIp = ipWords(ipB6)
	}
	if anyAddr {
		cfg.AnyAddr = 1
	}
	zero := uint32(0)
	if err := objs.TcpSrvCfgMap.Put(&zero, &cfg); err != nil {
		t.Fatal(err)
	}
}

// toServer builds a segment from the client (A, port 10000) to the responder (B:5201).
func toServer(v6 bool, seq, ack uint32, flags uint8, payload int) seg {
	s := seg{v6: v6, srcMAC: macA, dstMAC: macB, src: ipA4, dst: ipB4, sport: testPortBase, dport: testDstPort,
		seq: seq, ack: ack, flags: flags, win: 65535, payloadLen: payload}
	if v6 {
		s.src, s.dst = ipA6, ipB6
	}
	return s
}

func srvKey(v6 bool) BpfTcpSrvKey {
	k := BpfTcpSrvKey{Addr: ipWords(ipA4), Local: ipWords(ipB4), Port: testPortBase}
	if v6 {
		k.Addr = ipWords(ipA6)
		k.Local = ipWords(ipB6)
	}
	return k
}

func srvStats(t *testing.T, objs *BpfObjects) BpfTcpSrvStats {
	t.Helper()
	n, _ := ebpf.PossibleCPU()
	recs := make([]BpfTcpSrvStats, n)
	zero := uint32(0)
	if err := objs.TcpSrvStatsMap.Lookup(&zero, &recs); err != nil {
		t.Fatal(err)
	}
	var s BpfTcpSrvStats
	for _, r := range recs {
		s.RecycledEst += r.RecycledEst
		s.BadLen += r.BadLen
		s.BytesRcvd += r.BytesRcvd
	}
	return s
}

func srvFlow(t *testing.T, objs *BpfObjects, v6 bool) (BpfTcpSrvFlow, bool) {
	t.Helper()
	k := srvKey(v6)
	var f BpfTcpSrvFlow
	if err := objs.TcpSrvFlowMap.Lookup(&k, &f); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return f, false
		}
		t.Fatal(err)
	}
	return f, true
}

func srvRun(t *testing.T, objs *BpfObjects, s seg) (uint32, decoded) {
	t.Helper()
	ret, out := runProg(t, objs.XdpRxTcpServer, buildSeg(t, s))
	if ret != xdpTx {
		return ret, decoded{}
	}
	return ret, decode(t, out)
}

// handshake runs SYN / SYN-ACK / ACK and returns the responder's ISN.
func handshake(t *testing.T, objs *BpfObjects, v6 bool) uint32 {
	t.Helper()
	syn := toServer(v6, 100, 0, tcpSYN, 0)
	syn.opts = []layers.TCPOption{{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}}
	ret, d := srvRun(t, objs, syn)
	if ret != xdpTx || tcpFlags(d.tcp) != tcpSYN|tcpACK || d.tcp.Ack != 101 {
		t.Fatalf("SYN: ret %d", ret)
	}
	iss := d.tcp.Seq
	if ret, _ := srvRun(t, objs, toServer(v6, 101, iss+1, tcpACK, 0)); ret != xdpDrop {
		t.Fatalf("handshake ACK: ret %d, want XDP_DROP", ret)
	}
	return iss
}

func TestTcpServerSynAckOptions(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		objs := loadTCPObjs(t)
		setupServer(t, objs, v6, 1, false)
		syn := toServer(v6, 100, 0, tcpSYN, 0)
		syn.opts = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{9}},
		}
		ret, d := srvRun(t, objs, syn)
		if ret != xdpTx || tcpFlags(d.tcp) != tcpSYN|tcpACK || d.tcp.Ack != 101 {
			t.Fatalf("v6=%v: ret %d", v6, ret)
		}
		var mss uint16
		var ws = -1
		for _, o := range d.tcp.Options {
			switch o.OptionType {
			case layers.TCPOptionKindMSS:
				mss = binary.BigEndian.Uint16(o.OptionData)
			case layers.TCPOptionKindWindowScale:
				ws = int(o.OptionData[0])
			}
		}
		if mss != 1448 || ws != 7 {
			t.Fatalf("v6=%v: SYN-ACK options mss=%d ws=%d", v6, mss, ws)
		}
		if f, ok := srvFlow(t, objs, v6); !ok || f.State != tsSynRcvd || f.RcvNxt != 101 {
			t.Fatalf("v6=%v: flow %+v ok=%v", v6, f, ok)
		}
	}
	// No window scale offered: none returned.
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	_, d := srvRun(t, objs, toServer(false, 100, 0, tcpSYN, 0))
	for _, o := range d.tcp.Options {
		if o.OptionType == layers.TCPOptionKindWindowScale {
			t.Fatal("window scale returned although the client did not offer it")
		}
	}
}

func TestTcpServerRetransmittedSynRefreshesAge(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	_, d1 := srvRun(t, objs, toServer(false, 100, 0, tcpSYN, 0))
	f, _ := srvFlow(t, objs, false)
	f.LastNs = 1
	k := srvKey(false)
	if err := objs.TcpSrvFlowMap.Put(&k, &f); err != nil {
		t.Fatal(err)
	}
	_, d2 := srvRun(t, objs, toServer(false, 100, 0, tcpSYN, 0))
	if d2.tcp.Seq != d1.tcp.Seq {
		t.Fatal("retransmitted SYN got a different ISN")
	}
	if f, _ := srvFlow(t, objs, false); f.LastNs <= 1 {
		t.Fatal("retransmitted SYN did not refresh last_ns")
	}
}

func TestTcpServerDataAckEvery(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 2, false)
	iss := handshake(t, objs, false)
	// 1st in-order segment: held back (ack every 2)
	if ret, _ := srvRun(t, objs, toServer(false, 101, iss+1, tcpACK, 1000)); ret != xdpDrop {
		t.Fatalf("1st segment: ret %d, want XDP_DROP", ret)
	}
	// 2nd: acked
	ret, d := srvRun(t, objs, toServer(false, 1101, iss+1, tcpACK, 1000))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpACK || d.tcp.Ack != 2101 || d.tcp.Seq != iss+1 {
		t.Fatalf("2nd segment: ret %d", ret)
	}
	// PSH: acked immediately
	if ret, d := srvRun(t, objs, toServer(false, 2101, iss+1, tcpACK|tcpPSH, 10)); ret != xdpTx || d.tcp.Ack != 2111 {
		t.Fatalf("PSH segment: ret %d", ret)
	}
	// Out of order (hole): duplicate ACK at rcv_nxt
	if ret, d := srvRun(t, objs, toServer(false, 9999, iss+1, tcpACK, 100)); ret != xdpTx || d.tcp.Ack != 2111 {
		t.Fatalf("out-of-order: ret %d", ret)
	}
	if f, _ := srvFlow(t, objs, false); f.BytesRcvd != 2010 {
		t.Fatalf("bytes_rcvd = %d", f.BytesRcvd)
	}
}

func TestTcpServerClose(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, true, 1, false)
	iss := handshake(t, objs, true)
	ret, d := srvRun(t, objs, toServer(true, 101, iss+1, tcpFIN|tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Seq != iss+1 || d.tcp.Ack != 102 {
		t.Fatalf("FIN: ret %d", ret)
	}
	// FIN_WAIT_2 probe (ACK not covering our FIN): FIN+ACK is resent.
	ret, d = srvRun(t, objs, toServer(true, 102, iss+1, tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Seq != iss+1 {
		t.Fatalf("probe: ret %d", ret)
	}
	// The peer retransmits its FIN (our FIN+ACK lost): FIN+ACK again.
	ret, d = srvRun(t, objs, toServer(true, 101, iss+1, tcpFIN|tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Seq != iss+1 || d.tcp.Ack != 102 {
		t.Fatalf("FIN retransmit: ret %d", ret)
	}
	// Final ACK: entry removed.
	if ret, _ := srvRun(t, objs, toServer(true, 102, iss+2, tcpACK, 0)); ret != xdpDrop {
		t.Fatalf("final ACK: ret %d", ret)
	}
	if _, ok := srvFlow(t, objs, true); ok {
		t.Fatal("entry not removed after the final ACK")
	}
}

func TestTcpServerResets(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	// stray ACK: <SEQ=SEG.ACK><CTL=RST>
	ret, d := srvRun(t, objs, toServer(false, 500, 777, tcpACK, 10))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpRST || d.tcp.Seq != 777 {
		t.Fatalf("stray ACK: ret %d", ret)
	}
	// stray segment without ACK: <SEQ=0><ACK=SEG.SEQ+SEG.LEN+FIN><CTL=RST,ACK>
	ret, d = srvRun(t, objs, toServer(false, 500, 0, tcpFIN, 10))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpRST|tcpACK || d.tcp.Seq != 0 || d.tcp.Ack != 511 {
		t.Fatalf("stray no-ACK: ret %d flags %#x ack %d", ret, tcpFlags(d.tcp), d.tcp.Ack)
	}
	// RST is never answered
	if ret, _ := srvRun(t, objs, toServer(false, 500, 0, tcpRST, 0)); ret != xdpDrop {
		t.Fatalf("RST answered: ret %d", ret)
	}
	// SYN_RCVD with a wrong ACK: RST
	srvRun(t, objs, toServer(false, 100, 0, tcpSYN, 0))
	ret, d = srvRun(t, objs, toServer(false, 101, 12345, tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpRST || d.tcp.Seq != 12345 {
		t.Fatalf("SYN_RCVD bad ACK: ret %d", ret)
	}
}

func TestTcpServerTrimsPartialOverlap(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	iss := handshake(t, objs, false)
	if ret, d := srvRun(t, objs, toServer(false, 101, iss+1, tcpACK, 1000)); ret != xdpTx || d.tcp.Ack != 1101 {
		t.Fatalf("1st segment: ret %d", ret)
	}
	// Repacketized retransmission: 601..1601, of which 1101..1601 is new.
	if ret, d := srvRun(t, objs, toServer(false, 601, iss+1, tcpACK, 1000)); ret != xdpTx || d.tcp.Ack != 1601 {
		t.Fatalf("overlapping segment: ret %d ack %d, want 1601", ret, d.tcp.Ack)
	}
	if f, _ := srvFlow(t, objs, false); f.BytesRcvd != 1500 {
		t.Fatalf("bytes_rcvd = %d, want 1500", f.BytesRcvd)
	}
	// Fully duplicate data with a FIN at rcv_nxt: the FIN is accepted.
	ret, d := srvRun(t, objs, toServer(false, 1101, iss+1, tcpFIN|tcpACK, 500))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Ack != 1602 {
		t.Fatalf("duplicate data + FIN: ret %d flags %#x ack %d", ret, tcpFlags(d.tcp), d.tcp.Ack)
	}
	if f, _ := srvFlow(t, objs, false); f.BytesRcvd != 1500 {
		t.Fatalf("bytes_rcvd = %d after duplicate, want 1500", f.BytesRcvd)
	}
}

func TestTcpServerDropsBadLength(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		objs := loadTCPObjs(t)
		setupServer(t, objs, v6, 1, false)
		iss := handshake(t, objs, v6)
		// Header-only frame whose IP header claims 1000 bytes of payload.
		frame := buildSeg(t, toServer(v6, 101, iss+1, tcpACK, 0))
		if v6 {
			binary.BigEndian.PutUint16(frame[14+4:], 20+1000)
		} else {
			binary.BigEndian.PutUint16(frame[14+2:], 20+20+1000)
		}
		if ret, _ := runProg(t, objs.XdpRxTcpServer, frame); ret != xdpDrop {
			t.Fatalf("v6=%v: truncated segment: ret %d, want XDP_DROP", v6, ret)
		}
		if f, _ := srvFlow(t, objs, v6); f.BytesRcvd != 0 || f.RcvNxt != 101 {
			t.Fatalf("v6=%v: truncated segment changed the flow: %+v", v6, f)
		}
		if st := srvStats(t, objs); st.BadLen != 1 {
			t.Fatalf("v6=%v: bad_len = %d", v6, st.BadLen)
		}
	}
}

func TestTcpServerKeysOnLocalAddress(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, true) // wildcard listen address
	iss := handshake(t, objs, false)
	// Same peer address and port, another local address: a separate flow.
	syn := toServer(false, 5000, 0, tcpSYN, 0)
	syn.dst = net.IP{192, 168, 110, 3}
	if ret, d := srvRun(t, objs, syn); ret != xdpTx || d.tcp.Ack != 5001 {
		t.Fatalf("second SYN: ret %d", ret)
	}
	if f, ok := srvFlow(t, objs, false); !ok || f.State != tsEstablished || f.Iss != iss {
		t.Fatalf("first flow disturbed: %+v ok=%v", f, ok)
	}
	if st := srvStats(t, objs); st.RecycledEst != 0 {
		t.Fatalf("recycled_est = %d, want 0", st.RecycledEst)
	}
	// A new SYN on the first flow's own key replaces it and is counted.
	srvRun(t, objs, toServer(false, 9000, 0, tcpSYN, 0))
	if st := srvStats(t, objs); st.RecycledEst != 1 {
		t.Fatalf("recycled_est = %d, want 1", st.RecycledEst)
	}
}

func TestTcpServerAcksKeepalive(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	iss := handshake(t, objs, false)
	// Linux keepalive: empty ACK with seq = rcv_nxt - 1.
	ret, d := srvRun(t, objs, toServer(false, 100, iss+1, tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpACK || d.tcp.Ack != 101 || d.tcp.Seq != iss+1 {
		t.Fatalf("keepalive: ret %d", ret)
	}
	// An in-order pure ACK is still not answered.
	if ret, _ := srvRun(t, objs, toServer(false, 101, iss+1, tcpACK, 0)); ret != xdpDrop {
		t.Fatalf("in-order ACK: ret %d, want XDP_DROP", ret)
	}
	// FIN ahead of missing data: duplicate ACK, FIN not accepted.
	ret, d = srvRun(t, objs, toServer(false, 600, iss+1, tcpFIN|tcpACK, 0))
	if ret != xdpTx || tcpFlags(d.tcp) != tcpACK || d.tcp.Ack != 101 {
		t.Fatalf("early FIN: ret %d flags %#x ack %d", ret, tcpFlags(d.tcp), d.tcp.Ack)
	}
	if f, _ := srvFlow(t, objs, false); f.State != tsEstablished {
		t.Fatalf("early FIN changed the state to %d", f.State)
	}
}

func TestTcpServerPassesFirstFragment(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	frame := buildSeg(t, toServer(false, 100, 0, tcpSYN, 0))
	frame[14+6] |= 0x20 // MF, offset 0
	if ret, out := runProg(t, objs.XdpRxTcpServer, frame); ret != xdpPass || !bytes.Equal(out, frame) {
		t.Fatalf("first fragment: ret %d, want unchanged XDP_PASS", ret)
	}
	if _, ok := srvFlow(t, objs, false); ok {
		t.Fatal("first fragment created a flow")
	}
}

func TestTcpServerPassesForeignTraffic(t *testing.T) {
	objs := loadTCPObjs(t)
	setupServer(t, objs, false, 1, false)
	for name, s := range map[string]seg{
		"other port": func() seg { s := toServer(false, 1, 0, tcpSYN, 0); s.dport = 22; return s }(),
		"other address": func() seg {
			s := toServer(false, 1, 0, tcpSYN, 0)
			s.dst = net.IP{192, 168, 110, 77}
			return s
		}(),
		"ipv6 while ipv4 configured": toServer(true, 1, 0, tcpSYN, 0),
	} {
		in := buildSeg(t, s)
		ret, out := runProg(t, objs.XdpRxTcpServer, in)
		if ret != xdpPass || !bytes.Equal(out[:len(in)], in) {
			t.Fatalf("%s: ret %d (want XDP_PASS, unmodified)", name, ret)
		}
	}
	// any_addr accepts another destination address of the family
	setupServer(t, objs, false, 1, true)
	s := toServer(false, 1, 0, tcpSYN, 0)
	s.dst = net.IP{192, 168, 110, 77}
	if ret, _ := srvRun(t, objs, s); ret != xdpTx {
		t.Fatalf("any_addr: ret %d", ret)
	}
}

var _ = xdpAborted
var _ = tfClosed
var _ = tfDone
var _ = tsEstablished
var _ = tsLastAck
