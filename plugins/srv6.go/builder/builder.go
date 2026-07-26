// Package builder constructs SRv6 (RFC 8754) base packets and their checksum
// specs. It deliberately depends only on gopacket and the host-compatible parts
// of pkg/guest (types + checksum-spec helpers), never on the wasm-only goshim /
// host-import surface, so it can be unit tested with a plain `go test` on the
// host.
//
// The Segment Routing Header is assembled as raw bytes (full control over the
// field layout and stable offsets for the diff/checksum machinery) and
// concatenated with a separately serialized inner packet; gopacket then
// serializes the outer Ethernet/IPv6 around that payload with FixLengths, so
// the IPv6 payload length covers SRH + inner without manual fixups.
//
// The outer IPv6 header has no checksum and carries no transport of its own,
// so only inner checksum specs are emitted: inner IPv4 header + inner UDP for
// the IPv4-carrying modes, inner UDP (IPv6 pseudo header) for ModeIPv6.
package builder

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// Mode selects what the SRH encapsulates, i.e. the SRH next-header value and
// the inner frame layout.
type Mode int

const (
	// ModeL3VPNIPv4 carries an inner IPv4/UDP packet (SRH next header 4, End.DX4/DT4-style).
	ModeL3VPNIPv4 Mode = iota
	// ModeL2VPNEth carries an inner Ethernet frame with IPv4/UDP inside (SRH next header 143, End.DX2-style).
	ModeL2VPNEth
	// ModeIPv6 carries an inner IPv6/UDP packet (SRH next header 41, End.DX6/DT6-style).
	ModeIPv6
)

// ParseMode maps the JSON `mode` string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "l3vpn_ipv4":
		return ModeL3VPNIPv4, nil
	case "l2vpn_eth":
		return ModeL2VPNEth, nil
	case "ipv6":
		return ModeIPv6, nil
	}
	return 0, fmt.Errorf("mode must be 'l3vpn_ipv4', 'l2vpn_eth' or 'ipv6', got %q", s)
}

// NextHeader returns the SRH next-header protocol number for the mode.
func (m Mode) NextHeader() uint8 {
	switch m {
	case ModeL2VPNEth:
		return 143 // Ethernet (RFC 8986)
	case ModeIPv6:
		return 41 // IPv6-in-IPv6
	default:
		return 4 // IPv4-in-IPv6 (IPIP)
	}
}

// Fixed layer sizes used to derive offsets.
const (
	ethLen      = guest.EthernetHeaderLen // 14
	ipv4Len     = guest.IPv4HeaderLen     // 20
	ipv6Len     = guest.IPv6HeaderLen     // 40
	udpLen      = guest.UDPHeaderLen      // 8
	srhFixedLen = 8                       // SRH before the segment list
	segLen      = 16                      // one IPv6 segment
)

// srhRoutingTypeSRH is the routing-type value assigned to the SRH (RFC 8754).
const srhRoutingTypeSRH = 4

// MaxSegments is the largest segment-list length whose SRH still fits the
// 8-bit Hdr Ext Len field ((8+16n)/8-1 <= 255 → n <= 127).
const MaxSegments = 127

// FlowLabelMax is the largest value representable in the 20-bit IPv6 flow
// label field.
const FlowLabelMax = 0xFFFFF

// PacketParams fully describes one SRv6 frame to build. main.go fills this
// from the JSON GeneratorRequest; the builder stays free of JSON/default
// concerns.
type PacketParams struct {
	// outer L2/L3
	SrcMAC, DstMAC [6]byte
	SrcIP, DstIP   string // outer IPv6 addresses
	TrafficClass   uint8
	FlowLabel      uint32 // 20-bit; base value when the flow label is swept

	// SRH
	Mode     Mode
	// Segments is the pre-parsed SID list in visiting order: Segments[0] is the
	// first segment to visit and Segments[n-1] the final one. buildSRH reverses
	// it into the on-wire order (RFC 8754).
	Segments []net.IP
	SRHTag   uint16   // base value when the tag is swept

	// inner L2 (ModeL2VPNEth only)
	InnerSrcMAC, InnerDstMAC [6]byte

	// inner L3/L4. InnerSrcIP/InnerDstIP hold IPv4 addresses for
	// ModeL3VPNIPv4/ModeL2VPNEth and IPv6 addresses for ModeIPv6.
	InnerSrcIP, InnerDstIP     string
	InnerSrcPort, InnerDstPort uint16
}

// PacketInfo is the built base packet plus named byte offsets used to drive
// VariableParams and ChecksumSpec construction.
type PacketInfo struct {
	Data      []byte
	Offsets   map[string]uint64
	Checksums []guest.ChecksumSpec
}

// srhLen returns the SRH length for the configured segment list.
func (p *PacketParams) srhLen() int {
	return srhFixedLen + segLen*len(p.Segments)
}

// innerOverhead returns the inner header bytes before the payload.
func (p *PacketParams) innerOverhead() int {
	switch p.Mode {
	case ModeL2VPNEth:
		return ethLen + ipv4Len + udpLen // 42
	case ModeIPv6:
		return ipv6Len + udpLen // 48
	default:
		return ipv4Len + udpLen // 28
	}
}

// MinFrameLen is the smallest total frame length (including the outer Ethernet
// header, excluding FCS) that can hold all headers with a zero-length inner
// payload. With one segment: 106 (l3vpn_ipv4), 120 (l2vpn_eth), 126 (ipv6);
// each extra segment adds 16.
func MinFrameLen(p PacketParams) int {
	return ethLen + ipv6Len + p.srhLen() + p.innerOverhead()
}

// buildSRH assembles the raw Segment Routing Header: next header(1) + hdr ext
// len(1) + routing type(1) + segments left(1) + last entry(1) + flags(1) +
// tag(2) + segment list. segs is in visiting order; per RFC 8754 the list is
// stored reversed, so Segment List[0] (the first wire slot) holds the final
// segment segs[n-1], and Segments Left starts at n-1 pointing at Segment
// List[n-1] = segs[0], the first segment to visit.
func buildSRH(nextHeader uint8, tag uint16, segs []net.IP) []byte {
	srhLen := srhFixedLen + segLen*len(segs)
	b := make([]byte, srhLen)
	b[0] = nextHeader
	b[1] = uint8(srhLen/8 - 1)
	b[2] = srhRoutingTypeSRH
	b[3] = uint8(len(segs) - 1) // segments left
	b[4] = uint8(len(segs) - 1) // last entry
	// b[5] flags = 0
	binary.BigEndian.PutUint16(b[6:8], tag)
	off := srhFixedLen
	for i := len(segs) - 1; i >= 0; i-- {
		copy(b[off:off+segLen], segs[i].To16())
		off += segLen
	}
	return b
}

// buildInnerL3VPN serializes the inner IPv4/UDP packet (ModeL3VPNIPv4).
func buildInnerL3VPN(p *PacketParams, payload []byte) ([]byte, error) {
	innerIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(p.InnerSrcIP),
		DstIP:    net.ParseIP(p.InnerDstIP),
		Protocol: layers.IPProtocolUDP,
	}
	innerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.InnerSrcPort),
		DstPort: layers.UDPPort(p.InnerDstPort),
	}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("inner SetNetworkLayerForChecksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, innerIP, innerUDP, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize inner frame: %w", err)
	}
	return buf.Bytes(), nil
}

// buildInnerL2VPN serializes the inner Ethernet/IPv4/UDP frame (ModeL2VPNEth).
func buildInnerL2VPN(p *PacketParams, payload []byte) ([]byte, error) {
	innerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(p.InnerSrcMAC[:]),
		DstMAC:       net.HardwareAddr(p.InnerDstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	innerIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(p.InnerSrcIP),
		DstIP:    net.ParseIP(p.InnerDstIP),
		Protocol: layers.IPProtocolUDP,
	}
	innerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.InnerSrcPort),
		DstPort: layers.UDPPort(p.InnerDstPort),
	}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("inner SetNetworkLayerForChecksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, innerEth, innerIP, innerUDP, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize inner frame: %w", err)
	}
	return buf.Bytes(), nil
}

// buildInnerIPv6 serializes the inner IPv6/UDP packet (ModeIPv6). The UDP
// checksum is computed over the inner IPv6 pseudo header (mandatory for UDP
// over IPv6, RFC 8200).
func buildInnerIPv6(p *PacketParams, payload []byte) ([]byte, error) {
	innerIP := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(p.InnerSrcIP),
		DstIP:      net.ParseIP(p.InnerDstIP),
		NextHeader: layers.IPProtocolUDP,
	}
	innerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.InnerSrcPort),
		DstPort: layers.UDPPort(p.InnerDstPort),
	}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("inner SetNetworkLayerForChecksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, innerIP, innerUDP, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize inner frame: %w", err)
	}
	return buf.Bytes(), nil
}

// BuildSRv6Packet builds a single SRv6 frame of exactly totalLen bytes (the
// on-wire length including the 14-byte outer Ethernet header, excluding FCS).
func BuildSRv6Packet(p PacketParams, totalLen int) (*PacketInfo, error) {
	if len(p.Segments) == 0 {
		return nil, fmt.Errorf("at least one segment is required")
	}
	if len(p.Segments) > MaxSegments {
		return nil, fmt.Errorf("segment list length %d exceeds the maximum %d", len(p.Segments), MaxSegments)
	}
	for i, seg := range p.Segments {
		if seg.To16() == nil || seg.To4() != nil {
			return nil, fmt.Errorf("segment %d is not an IPv6 address", i)
		}
	}
	if p.FlowLabel > FlowLabelMax {
		return nil, fmt.Errorf("flow label %d exceeds the 20-bit maximum %d", p.FlowLabel, FlowLabelMax)
	}
	minLen := MinFrameLen(p)
	if totalLen < minLen {
		return nil, fmt.Errorf("totalLen %d is smaller than the minimum SRv6 frame length %d", totalLen, minLen)
	}
	payloadLen := totalLen - minLen
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var (
		innerBytes []byte
		err        error
	)
	switch p.Mode {
	case ModeL2VPNEth:
		innerBytes, err = buildInnerL2VPN(&p, payload)
	case ModeIPv6:
		innerBytes, err = buildInnerIPv6(&p, payload)
	default:
		innerBytes, err = buildInnerL3VPN(&p, payload)
	}
	if err != nil {
		return nil, err
	}
	// gopacket pads Ethernet frames shorter than 60 bytes on serialization. The
	// inner frame is encapsulated (no FCS/minimum-size requirement of its own),
	// so strip the pad to keep totalLen exact; the inner IP/UDP length fields
	// already exclude it.
	if want := p.innerOverhead() + payloadLen; len(innerBytes) > want {
		innerBytes = innerBytes[:want]
	}

	// SRH + inner as one opaque IPv6 payload: FixLengths then writes the IPv6
	// payload length over both, with no manual fixup.
	srhBytes := buildSRH(p.Mode.NextHeader(), p.SRHTag, p.Segments)
	ip6Payload := make([]byte, 0, len(srhBytes)+len(innerBytes))
	ip6Payload = append(ip6Payload, srhBytes...)
	ip6Payload = append(ip6Payload, innerBytes...)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(p.SrcMAC[:]),
		DstMAC:       net.HardwareAddr(p.DstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: p.TrafficClass,
		FlowLabel:    p.FlowLabel,
		HopLimit:     64,
		SrcIP:        net.ParseIP(p.SrcIP),
		DstIP:        net.ParseIP(p.DstIP),
		NextHeader:   layers.IPProtocolIPv6Routing, // 43
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip6, gopacket.Payload(ip6Payload),
	); err != nil {
		return nil, fmt.Errorf("serialize outer: %w", err)
	}
	data := buf.Bytes()

	// All offsets are derived from the fixed outer layout; nothing is hardcoded
	// to a specific segment count.
	srhStart := ethLen + ipv6Len // 54
	innerStart := srhStart + p.srhLen()
	innerL3 := innerStart
	if p.Mode == ModeL2VPNEth {
		innerL3 += ethLen
	}

	info := &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			// version/TC/flow-label word; the 4-byte flow-label diff starts here.
			"outer.ip6.start": uint64(ethLen),
			"outer.ip6.src":   uint64(ethLen + 8),
			"outer.ip6.dst":   uint64(ethLen + 24),
			"srh.start":       uint64(srhStart),
			"srh.tag":         uint64(srhStart + 6),
			"inner.start":     uint64(innerStart),
		},
	}
	if p.Mode == ModeIPv6 {
		udpStart := innerL3 + ipv6Len
		info.Offsets["inner.ip6.start"] = uint64(innerL3)
		info.Offsets["inner.ip6.src"] = uint64(innerL3 + 8)
		info.Offsets["inner.ip6.dst"] = uint64(innerL3 + 24)
		info.Offsets["inner.udp.src"] = uint64(udpStart)
		info.Offsets["inner.udp.dst"] = uint64(udpStart + 2)
		// The inner IPv6 header directly precedes UDP (next header 17), so the
		// data plane resolves the transport without walking the outer SRH.
		info.Checksums = []guest.ChecksumSpec{
			guest.IPv6TransportChecksumSpec(uint16(innerL3), uint16(udpStart), guest.UDPChecksumFieldOffset),
		}
		return info, nil
	}
	udpStart := innerL3 + ipv4Len
	info.Offsets["inner.ip.start"] = uint64(innerL3)
	info.Offsets["inner.ip.src"] = uint64(innerL3 + 12)
	info.Offsets["inner.ip.dst"] = uint64(innerL3 + 16)
	info.Offsets["inner.udp.src"] = uint64(udpStart)
	info.Offsets["inner.udp.dst"] = uint64(udpStart + 2)
	info.Checksums = buildInnerIPv4ChecksumSpecs(uint16(innerL3))
	return info, nil
}

// buildInnerIPv4ChecksumSpecs returns the checksum specs for an inner
// IPv4/UDP packet starting at innerL3: the inner IPv4 header checksum and the
// inner UDP checksum (IPv4 pseudo header). The outer IPv6 header has no
// checksum, so no outer spec is emitted.
func buildInnerIPv4ChecksumSpecs(innerL3 uint16) []guest.ChecksumSpec {
	return guest.IPv4UDPChecksumSpecs(innerL3)
}
