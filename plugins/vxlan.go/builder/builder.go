// Package builder constructs VXLAN (RFC 7348) base packets and their checksum
// specs. It deliberately depends only on gopacket and the host-compatible parts
// of pkg/guest (types + IPv4UDPChecksumSpecs), never on the wasm-only goshim /
// host-import surface, so it can be unit tested with a plain `go test` on the
// host.
//
// The VXLAN header is assembled as raw bytes (full control over the flags and
// the 24-bit VNI offset) and concatenated with a separately serialized inner
// Ethernet/IPv4/UDP frame. gopacket then serializes the outer
// Ethernet/IPv4/UDP around that payload. We do NOT use gopacket's built-in
// VXLAN layer, to keep byte offsets explicit and stable for the diff/checksum
// machinery.
//
// Unlike GTP-U, the outer UDP checksum is left 0 (the RFC 7348 default) and no
// outer UDP checksum spec is emitted, so the data plane never writes it.
package builder

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// VXLANPort is the IANA-assigned VXLAN UDP destination port.
const VXLANPort = 4789

// Fixed layer sizes used to derive offsets.
const (
	ethLen   = guest.EthernetHeaderLen // 14
	ipv4Len  = guest.IPv4HeaderLen     // 20
	udpLen   = guest.UDPHeaderLen      // 8
	vxlanLen = 8                       // VXLAN header
	// inner overhead: inner Ethernet + inner IPv4 + inner UDP.
	innerOverhead = ethLen + ipv4Len + udpLen
)

// vxlanFlagValidVNI is the VXLAN flags byte with the I (VNI valid) bit set.
const vxlanFlagValidVNI = 0x08

// vniMax is the largest value representable in the 24-bit VNI field.
const vniMax = 0xFFFFFF

// PacketParams fully describes one VXLAN frame to build. main.go fills this from
// the JSON GeneratorRequest; the builder stays free of JSON/default concerns.
type PacketParams struct {
	// outer L2/L3/L4
	SrcMAC, DstMAC [6]byte
	SrcIP, DstIP   string
	OuterSrcPort   uint16
	OuterDstPort   uint16

	// VXLAN
	VNI uint32

	// inner L2 (the encapsulated Ethernet frame)
	InnerSrcMAC, InnerDstMAC [6]byte

	// inner L3/L4
	InnerSrcIP, InnerDstIP     string
	InnerSrcPort, InnerDstPort uint16
	// InnerUDPChecksum, when false (the default), leaves the inner UDP checksum 0
	// (disabled — legal over IPv4) and emits no inner UDP checksum spec, so the
	// data plane never touches it. When true the checksum is computed and a spec
	// is emitted so the data plane keeps it correct.
	InnerUDPChecksum bool

	// InnerL2Only, when true, encapsulates only an inner Ethernet header (no inner
	// IPv4/UDP) plus padding. This drops the minimum frame to 64 bytes
	// (14+20+8+8+14), so the generator can emit minimum-size VXLAN frames for
	// peak-pps testing. The inner IP/UDP offsets and the inner checksum specs are
	// omitted in this mode.
	InnerL2Only bool
}

// PacketInfo is the built base packet plus named byte offsets used to drive
// VariableParams and ChecksumSpec construction.
type PacketInfo struct {
	Data      []byte
	Offsets   map[string]uint64
	Checksums []guest.ChecksumSpec
}

// MinFrameLen is the smallest total frame length (including the outer Ethernet
// header) that can hold all headers with a zero-length inner payload. In
// l2-only mode the inner frame is just an Ethernet header, giving a 64-byte
// minimum.
func MinFrameLen(p PacketParams) int {
	if p.InnerL2Only {
		return ethLen + ipv4Len + udpLen + vxlanLen + ethLen // 64
	}
	return ethLen + ipv4Len + udpLen + vxlanLen + innerOverhead // 92
}

// buildVXLANHeader assembles the raw 8-byte VXLAN header: flags(1) +
// reserved(3) + VNI(3) + reserved(1). The I bit marks the VNI valid.
func buildVXLANHeader(vni uint32) []byte {
	h := make([]byte, vxlanLen)
	h[0] = vxlanFlagValidVNI
	// VNI is a 24-bit field occupying bytes 4..6 (big-endian). Write it via a
	// uint32 then drop the high byte into the trailing reserved octet position,
	// which we immediately overwrite to 0.
	binary.BigEndian.PutUint32(h[4:8], vni<<8)
	h[7] = 0x00 // reserved
	return h
}

// buildInner serializes the inner Ethernet/IPv4/UDP frame with correct inner
// IP/UDP length fields and checksums.
func buildInner(p *PacketParams, payload []byte) ([]byte, error) {
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
	out := buf.Bytes()
	if !p.InnerUDPChecksum {
		// A zero UDP checksum is legal over IPv4 and means "not computed". With no
		// inner UDP checksum spec either, the data plane never writes this field,
		// so it cannot be left stale by the multi-variant (IMIX) base-reuse path.
		csumOff := ethLen + ipv4Len + guest.UDPChecksumFieldOffset
		out[csumOff] = 0
		out[csumOff+1] = 0
	}
	return out, nil
}

// buildInnerL2 builds an inner Ethernet header (no L3) followed by padding. Used
// by l2-only mode to reach a 64-byte minimum VXLAN frame. The EtherType is left
// 0x0000 (no upper-layer protocol); the frame is a deliberate stub for load
// testing, not a routable inner packet.
func buildInnerL2(p *PacketParams, payload []byte) []byte {
	b := make([]byte, ethLen+len(payload))
	copy(b[0:6], p.InnerDstMAC[:])
	copy(b[6:12], p.InnerSrcMAC[:])
	// b[12:14] EtherType = 0x0000 (no inner L3)
	copy(b[ethLen:], payload)
	return b
}

// BuildVXLANPacket builds a single VXLAN frame of exactly totalLen bytes (the
// on-wire length including the 14-byte outer Ethernet header, excluding FCS).
func BuildVXLANPacket(p PacketParams, totalLen int) (*PacketInfo, error) {
	minLen := MinFrameLen(p)
	if totalLen < minLen {
		return nil, fmt.Errorf("totalLen %d is smaller than the minimum VXLAN frame length %d", totalLen, minLen)
	}
	if p.VNI > vniMax {
		return nil, fmt.Errorf("vni %d exceeds the 24-bit maximum %d", p.VNI, vniMax)
	}
	payloadLen := totalLen - minLen
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var innerBytes []byte
	if p.InnerL2Only {
		innerBytes = buildInnerL2(&p, payload)
	} else {
		var err error
		innerBytes, err = buildInner(&p, payload)
		if err != nil {
			return nil, err
		}
	}
	vxlanHeader := buildVXLANHeader(p.VNI)
	vxlanPayload := make([]byte, 0, len(vxlanHeader)+len(innerBytes))
	vxlanPayload = append(vxlanPayload, vxlanHeader...)
	vxlanPayload = append(vxlanPayload, innerBytes...)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(p.SrcMAC[:]),
		DstMAC:       net.HardwareAddr(p.DstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	outerIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(p.SrcIP),
		DstIP:    net.ParseIP(p.DstIP),
		Protocol: layers.IPProtocolUDP,
	}
	outerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.OuterSrcPort),
		DstPort: layers.UDPPort(p.OuterDstPort),
	}
	// gopacket requires a network layer to serialize the UDP layer with
	// ComputeChecksums set (which we need for the outer IPv4 header checksum). It
	// computes an outer UDP checksum too, but VXLAN leaves that 0 (RFC 7348), so
	// we zero it again right after serialization.
	if err := outerUDP.SetNetworkLayerForChecksum(outerIP); err != nil {
		return nil, fmt.Errorf("outer SetNetworkLayerForChecksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, outerIP, outerUDP, gopacket.Payload(vxlanPayload),
	); err != nil {
		return nil, fmt.Errorf("serialize outer: %w", err)
	}
	data := buf.Bytes()
	// Force the outer UDP checksum to 0 in case gopacket computed one.
	outerUDPStart := ethLen + ipv4Len
	data[outerUDPStart+guest.UDPChecksumFieldOffset] = 0
	data[outerUDPStart+guest.UDPChecksumFieldOffset+1] = 0

	vxlanStart := ethLen + ipv4Len + udpLen // 42
	innerEthStart := vxlanStart + vxlanLen  // 50
	innerOff := innerEthStart + ethLen      // 64 (inner IPv4, ip mode only)
	info := &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"outer.udp.src": uint64(outerUDPStart),  // 34
			"vxlan.start":   uint64(vxlanStart),     // 42
			"vxlan.vni":     uint64(vxlanStart + 4), // 46 (24-bit VNI)
			"inner.start":   uint64(innerEthStart),  // 50 (inner Ethernet)
		},
	}
	if p.InnerL2Only {
		// L2-only: just the outer IPv4 header checksum (no inner L3/L4). The outer
		// UDP checksum stays 0 (RFC 7348), so no spec for it.
		info.Checksums = []guest.ChecksumSpec{guest.IPv4UDPChecksumSpecs(ethLen)[0]}
		return info, nil
	}
	info.Offsets["inner.ip.start"] = uint64(innerOff)          // 64
	info.Offsets["inner.ip.src"] = uint64(innerOff + 12)       // 76
	info.Offsets["inner.ip.dst"] = uint64(innerOff + 16)       // 80
	info.Offsets["inner.udp.src"] = uint64(innerOff + ipv4Len) // 84
	info.Checksums = buildChecksumSpecs(uint16(innerOff), p.InnerUDPChecksum)
	return info, nil
}

// buildChecksumSpecs returns the checksum specs the data plane recomputes.
//
// Unlike GTP-U, VXLAN leaves the outer UDP checksum 0, so no outer UDP spec is
// emitted. The result is [outer IPv4, inner IPv4] and, when includeInnerUDP is
// true, [outer IPv4, inner IPv4, inner UDP] — the inner UDP spec lets the data
// plane keep the inner UDP checksum correct (e.g. when the inner source port or
// inner source IP is varied).
func buildChecksumSpecs(innerOff uint16, includeInnerUDP bool) []guest.ChecksumSpec {
	// Reuse the outer IPv4 spec from the shared helper; drop its outer UDP entry.
	outerIPv4 := guest.IPv4UDPChecksumSpecs(ethLen)[0]
	innerIP := guest.ChecksumSpec{
		ChecksumOffset: innerOff + guest.IPv4ChecksumFieldOffset,
		HeaderStart:    innerOff,
		HeaderLen:      guest.IPv4HeaderLen,
		IPHeaderOffset: innerOff,
	}
	if !includeInnerUDP {
		return []guest.ChecksumSpec{outerIPv4, innerIP}
	}
	innerUDPStart := innerOff + ipv4Len
	innerUDP := guest.ChecksumSpec{
		ChecksumOffset: innerUDPStart + guest.UDPChecksumFieldOffset,
		HeaderStart:    innerUDPStart,
		HeaderLen:      0, // 0 = derive length from the inner IPv4 total length
		IPHeaderOffset: innerOff,
	}
	return []guest.ChecksumSpec{outerIPv4, innerIP, innerUDP}
}
