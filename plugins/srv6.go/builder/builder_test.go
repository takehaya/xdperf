package builder

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func testParams(mode Mode, segments []string) PacketParams {
	segs := make([]net.IP, len(segments))
	for i, s := range segments {
		segs[i] = net.ParseIP(s)
	}
	p := PacketParams{
		SrcMAC:       [6]byte{0x02, 0, 0, 0, 0, 0x01},
		DstMAC:       [6]byte{0x02, 0, 0, 0, 0, 0x02},
		SrcIP:        "2001:db8::1",
		DstIP:        "2001:db8:100::1",
		TrafficClass: 0,
		FlowLabel:    0x12345,
		Mode:         mode,
		Segments:     segs,
		SRHTag:       0xBEEF,
		InnerSrcMAC:  [6]byte{0xA2, 0, 0, 0, 0, 0x01},
		InnerDstMAC:  [6]byte{0xA2, 0, 0, 0, 0, 0x02},
		InnerSrcIP:   "192.168.0.1",
		InnerDstIP:   "192.168.0.2",
		InnerSrcPort: 1024,
		InnerDstPort: 5060,
	}
	if mode == ModeIPv6 {
		p.InnerSrcIP = "fd00::1"
		p.InnerDstIP = "fd00::2"
	}
	return p
}

func TestMinFrameLen(t *testing.T) {
	cases := []struct {
		mode Mode
		segs int
		want int
	}{
		{ModeL3VPNIPv4, 1, 106},
		{ModeL2VPNEth, 1, 120},
		{ModeIPv6, 1, 126},
		{ModeL3VPNIPv4, 3, 138},
		{ModeL2VPNEth, 3, 152},
		{ModeIPv6, 3, 158},
	}
	for _, c := range cases {
		segs := make([]string, c.segs)
		for i := range segs {
			segs[i] = "2001:db8:100::1"
		}
		if got := MinFrameLen(testParams(c.mode, segs)); got != c.want {
			t.Errorf("MinFrameLen(mode=%d, segs=%d) = %d, want %d", c.mode, c.segs, got, c.want)
		}
	}
}

func TestParseMode(t *testing.T) {
	for s, want := range map[string]Mode{"l3vpn_ipv4": ModeL3VPNIPv4, "l2vpn_eth": ModeL2VPNEth, "ipv6": ModeIPv6} {
		got, err := ParseMode(s)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = (%d, %v), want (%d, nil)", s, got, err, want)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Error("ParseMode(bogus) succeeded, want error")
	}
}

func TestBuildSRv6PacketErrors(t *testing.T) {
	// No segments.
	p := testParams(ModeL3VPNIPv4, nil)
	if _, err := BuildSRv6Packet(p, 200); err == nil {
		t.Error("empty segment list accepted, want error")
	}
	// Non-IPv6 segment.
	p = testParams(ModeL3VPNIPv4, []string{"192.0.2.1"})
	if _, err := BuildSRv6Packet(p, 200); err == nil {
		t.Error("IPv4 segment accepted, want error")
	}
	// Too many segments for the 8-bit Hdr Ext Len.
	segs := make([]string, MaxSegments+1)
	for i := range segs {
		segs[i] = "2001:db8:100::1"
	}
	p = testParams(ModeL3VPNIPv4, segs)
	if _, err := BuildSRv6Packet(p, 4000); err == nil {
		t.Error("128 segments accepted, want error")
	}
	// Frame shorter than the headers.
	p = testParams(ModeL3VPNIPv4, []string{"2001:db8:100::1"})
	if _, err := BuildSRv6Packet(p, MinFrameLen(p)-1); err == nil {
		t.Error("totalLen below minimum accepted, want error")
	}
	// Flow label out of range.
	p = testParams(ModeL3VPNIPv4, []string{"2001:db8:100::1"})
	p.FlowLabel = FlowLabelMax + 1
	if _, err := BuildSRv6Packet(p, 200); err == nil {
		t.Error("21-bit flow label accepted, want error")
	}
}

// TestBuildSRv6Packet builds every mode with 1 and 3 segments at the minimum
// and a larger length, and verifies the wire layout via decode.
func TestBuildSRv6Packet(t *testing.T) {
	segSets := [][]string{
		{"2001:db8:100::1"},
		{"2001:db8:100::1", "2001:db8:200::1", "2001:db8:300::1"},
	}
	for _, mode := range []Mode{ModeL3VPNIPv4, ModeL2VPNEth, ModeIPv6} {
		for _, segs := range segSets {
			p := testParams(mode, segs)
			for _, totalLen := range []int{MinFrameLen(p), 1400} {
				info, err := BuildSRv6Packet(p, totalLen)
				if err != nil {
					t.Fatalf("mode=%d segs=%d len=%d: %v", mode, len(segs), totalLen, err)
				}
				if len(info.Data) != totalLen {
					t.Fatalf("mode=%d: len(Data) = %d, want %d", mode, len(info.Data), totalLen)
				}
				verifyOuter(t, p, info)
				verifySRH(t, p, info)
				verifyInner(t, p, info)
				verifyChecksumSpecs(t, p, info)
			}
		}
	}
}

func verifyOuter(t *testing.T, p PacketParams, info *PacketInfo) {
	t.Helper()
	d := info.Data
	if et := binary.BigEndian.Uint16(d[12:14]); et != 0x86DD {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", et)
	}
	// version(4) | traffic class(8) | flow label(20)
	word := binary.BigEndian.Uint32(d[14:18])
	if v := word >> 28; v != 6 {
		t.Errorf("IPv6 version = %d, want 6", v)
	}
	if fl := word & 0xFFFFF; fl != p.FlowLabel {
		t.Errorf("flow label = 0x%05x, want 0x%05x", fl, p.FlowLabel)
	}
	// Payload length must cover SRH + inner with no manual fixup (regression
	// for the vpn_srv6.go hand-patched length).
	if plen := binary.BigEndian.Uint16(d[18:20]); int(plen) != len(d)-54 {
		t.Errorf("IPv6 payload length = %d, want %d", plen, len(d)-54)
	}
	if d[20] != 43 {
		t.Errorf("IPv6 next header = %d, want 43 (routing)", d[20])
	}
	if !net.IP(d[22:38]).Equal(net.ParseIP(p.SrcIP)) {
		t.Errorf("outer src IP = %v, want %s", net.IP(d[22:38]), p.SrcIP)
	}
	if !net.IP(d[38:54]).Equal(net.ParseIP(p.DstIP)) {
		t.Errorf("outer dst IP = %v, want %s", net.IP(d[38:54]), p.DstIP)
	}
	if info.Offsets["outer.ip6.start"] != 14 || info.Offsets["outer.ip6.src"] != 22 || info.Offsets["outer.ip6.dst"] != 38 {
		t.Errorf("outer offsets = %v, want start=14 src=22 dst=38", info.Offsets)
	}
}

func verifySRH(t *testing.T, p PacketParams, info *PacketInfo) {
	t.Helper()
	d := info.Data
	srh := d[info.Offsets["srh.start"]:]
	n := len(p.Segments)
	if info.Offsets["srh.start"] != 54 {
		t.Errorf("srh.start = %d, want 54", info.Offsets["srh.start"])
	}
	if srh[0] != p.Mode.NextHeader() {
		t.Errorf("SRH next header = %d, want %d", srh[0], p.Mode.NextHeader())
	}
	wantExtLen := uint8((8+16*n)/8 - 1)
	if srh[1] != wantExtLen {
		t.Errorf("SRH hdr ext len = %d, want %d", srh[1], wantExtLen)
	}
	if srh[2] != 4 {
		t.Errorf("SRH routing type = %d, want 4", srh[2])
	}
	if srh[3] != uint8(n-1) || srh[4] != uint8(n-1) {
		t.Errorf("SRH segments left/last entry = %d/%d, want %d", srh[3], srh[4], n-1)
	}
	if tag := binary.BigEndian.Uint16(srh[6:8]); tag != p.SRHTag {
		t.Errorf("SRH tag = 0x%04x, want 0x%04x", tag, p.SRHTag)
	}
	if info.Offsets["srh.tag"] != info.Offsets["srh.start"]+6 {
		t.Errorf("srh.tag offset = %d, want %d", info.Offsets["srh.tag"], info.Offsets["srh.start"]+6)
	}
	// Segment list is stored reversed: segments[0] in the last slot (RFC 8754).
	for i, seg := range p.Segments {
		slot := 8 + (n-1-i)*16
		got := net.IP(srh[slot : slot+16])
		if !got.Equal(seg) {
			t.Errorf("SRH slot %d = %v, want segments[%d] = %v", n-1-i, got, i, seg)
		}
	}
}

func verifyInner(t *testing.T, p PacketParams, info *PacketInfo) {
	t.Helper()
	inner := info.Data[info.Offsets["inner.start"]:]
	wantStart := 54 + 8 + 16*len(p.Segments)
	if int(info.Offsets["inner.start"]) != wantStart {
		t.Fatalf("inner.start = %d, want %d", info.Offsets["inner.start"], wantStart)
	}

	var pkt gopacket.Packet
	switch p.Mode {
	case ModeL2VPNEth:
		pkt = gopacket.NewPacket(inner, layers.LayerTypeEthernet, gopacket.Default)
		eth := pkt.Layer(layers.LayerTypeEthernet)
		if eth == nil {
			t.Fatal("inner Ethernet layer not decoded")
		}
		e := eth.(*layers.Ethernet)
		if !hwEqual(e.SrcMAC, p.InnerSrcMAC) || !hwEqual(e.DstMAC, p.InnerDstMAC) {
			t.Errorf("inner MACs = %v/%v, want %v/%v", e.SrcMAC, e.DstMAC, p.InnerSrcMAC, p.InnerDstMAC)
		}
	case ModeIPv6:
		pkt = gopacket.NewPacket(inner, layers.LayerTypeIPv6, gopacket.Default)
	default:
		pkt = gopacket.NewPacket(inner, layers.LayerTypeIPv4, gopacket.Default)
	}

	if p.Mode == ModeIPv6 {
		l := pkt.Layer(layers.LayerTypeIPv6)
		if l == nil {
			t.Fatal("inner IPv6 layer not decoded")
		}
		ip6 := l.(*layers.IPv6)
		if !ip6.SrcIP.Equal(net.ParseIP(p.InnerSrcIP)) || !ip6.DstIP.Equal(net.ParseIP(p.InnerDstIP)) {
			t.Errorf("inner IPv6 = %v→%v, want %s→%s", ip6.SrcIP, ip6.DstIP, p.InnerSrcIP, p.InnerDstIP)
		}
		if int(info.Offsets["inner.ip6.src"]) != int(info.Offsets["inner.ip6.start"])+8 {
			t.Errorf("inner.ip6.src offset mismatch: %v", info.Offsets)
		}
	} else {
		l := pkt.Layer(layers.LayerTypeIPv4)
		if l == nil {
			t.Fatal("inner IPv4 layer not decoded")
		}
		ip4 := l.(*layers.IPv4)
		if !ip4.SrcIP.Equal(net.ParseIP(p.InnerSrcIP)) || !ip4.DstIP.Equal(net.ParseIP(p.InnerDstIP)) {
			t.Errorf("inner IPv4 = %v→%v, want %s→%s", ip4.SrcIP, ip4.DstIP, p.InnerSrcIP, p.InnerDstIP)
		}
	}

	l := pkt.Layer(layers.LayerTypeUDP)
	if l == nil {
		t.Fatal("inner UDP layer not decoded")
	}
	udp := l.(*layers.UDP)
	if uint16(udp.SrcPort) != p.InnerSrcPort || uint16(udp.DstPort) != p.InnerDstPort {
		t.Errorf("inner UDP ports = %d→%d, want %d→%d", udp.SrcPort, udp.DstPort, p.InnerSrcPort, p.InnerDstPort)
	}
	// UDP checksum must be present (computed over the pseudo header).
	if udp.Checksum == 0 {
		t.Error("inner UDP checksum is 0, want computed")
	}
	// The inner UDP src offset must line up with the decoded layout.
	udpOff := int(info.Offsets["inner.udp.src"])
	if got := binary.BigEndian.Uint16(info.Data[udpOff : udpOff+2]); got != p.InnerSrcPort {
		t.Errorf("byte at inner.udp.src = %d, want %d", got, p.InnerSrcPort)
	}
}

func verifyChecksumSpecs(t *testing.T, p PacketParams, info *PacketInfo) {
	t.Helper()
	if p.Mode == ModeIPv6 {
		if len(info.Checksums) != 1 {
			t.Fatalf("checksums = %d, want 1 (inner UDP over IPv6)", len(info.Checksums))
		}
		cs := info.Checksums[0]
		if uint64(cs.IPHeaderOffset) != info.Offsets["inner.ip6.start"] {
			t.Errorf("UDP spec IPHeaderOffset = %d, want inner.ip6.start %d", cs.IPHeaderOffset, info.Offsets["inner.ip6.start"])
		}
		if uint64(cs.ChecksumOffset) != info.Offsets["inner.udp.src"]+guest.UDPChecksumFieldOffset {
			t.Errorf("UDP spec ChecksumOffset = %d, want %d", cs.ChecksumOffset, info.Offsets["inner.udp.src"]+guest.UDPChecksumFieldOffset)
		}
		return
	}
	if len(info.Checksums) != 2 {
		t.Fatalf("checksums = %d, want 2 (inner IPv4 + inner UDP)", len(info.Checksums))
	}
	ipSpec, udpSpec := info.Checksums[0], info.Checksums[1]
	innerL3 := info.Offsets["inner.ip.start"]
	if uint64(ipSpec.HeaderStart) != innerL3 || ipSpec.HeaderLen != guest.IPv4HeaderLen || uint64(ipSpec.IPHeaderOffset) != innerL3 {
		t.Errorf("inner IPv4 spec = %+v, want header at %d", ipSpec, innerL3)
	}
	if uint64(udpSpec.HeaderStart) != info.Offsets["inner.udp.src"] || udpSpec.HeaderLen != 0 || uint64(udpSpec.IPHeaderOffset) != innerL3 {
		t.Errorf("inner UDP spec = %+v, want header at %d, ip at %d", udpSpec, info.Offsets["inner.udp.src"], innerL3)
	}
}

func hwEqual(a net.HardwareAddr, b [6]byte) bool {
	return len(a) == 6 && net.HardwareAddr(b[:]).String() == a.String()
}
