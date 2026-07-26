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
	ethLen     = guest.EthernetHeaderLen // 14
	ipv4Len    = guest.IPv4HeaderLen     // 20
	udpLen     = guest.UDPHeaderLen      // 8
	vxlanLen   = 8                       // VXLAN header
	vlanTagLen = 4                       // one 802.1Q tag (TPID + TCI)
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

	// Optional outer 802.1Q VLAN tag (VXLAN underlay). VLANID == 0 means no tag
	// (the default) — the VLAN header is omitted entirely and all downstream
	// offsets are unshifted. VLANPCP is the 3-bit priority, only meaningful when
	// tagged.
	VLANID  uint16
	VLANPCP uint8

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

// vlanLen returns the outer 802.1Q tag length: 4 when tagged, 0 otherwise.
func (p *PacketParams) vlanLen() int {
	if p.VLANID != 0 {
		return vlanTagLen
	}
	return 0
}

// MinFrameLen is the smallest total frame length (including the outer Ethernet
// header) that can hold all headers with a zero-length inner payload. In
// l2-only mode the inner frame is just an Ethernet header, giving a 64-byte
// minimum (68 with an outer VLAN tag).
func MinFrameLen(p PacketParams) int {
	if p.InnerL2Only {
		return ethLen + p.vlanLen() + ipv4Len + udpLen + vxlanLen + ethLen // 64 (+4 tagged)
	}
	return ethLen + p.vlanLen() + ipv4Len + udpLen + vxlanLen + innerOverhead // 92 (+4 tagged)
}

// buildVXLANHeader assembles the raw 8-byte VXLAN header: flags(1) +
// reserved(3) + VNI(3) + reserved(1). The I bit marks the VNI valid.
func buildVXLANHeader(vni uint32) []byte {
	h := make([]byte, vxlanLen)
	h[0] = vxlanFlagValidVNI
	// VNI is a 24-bit field occupying bytes 4..6 (big-endian); byte 7 is reserved.
	h[4] = byte(vni >> 16)
	h[5] = byte(vni >> 8)
	h[6] = byte(vni)
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
		// gopacket pads Ethernet frames shorter than 60 bytes on serialization.
		// The inner frame is encapsulated (no FCS/minimum-size requirement of its
		// own), so strip the pad to keep totalLen exact; the inner IP/UDP length
		// fields already exclude it.
		if want := innerOverhead + payloadLen; len(innerBytes) > want {
			innerBytes = innerBytes[:want]
		}
	}
	vxlanHeader := buildVXLANHeader(p.VNI)
	vxlanPayload := make([]byte, 0, len(vxlanHeader)+len(innerBytes))
	vxlanPayload = append(vxlanPayload, vxlanHeader...)
	vxlanPayload = append(vxlanPayload, innerBytes...)

	vlanLen := p.vlanLen()
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
	// Assemble the layer stack, inserting an optional 802.1Q tag between the outer
	// Ethernet header and IPv4. When untagged the VLAN layer is omitted entirely.
	outerLayers := []gopacket.SerializableLayer{eth}
	if vlanLen > 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		outerLayers = append(outerLayers, &layers.Dot1Q{
			Priority:       p.VLANPCP,
			VLANIdentifier: p.VLANID,
			Type:           layers.EthernetTypeIPv4,
		})
	}
	outerLayers = append(outerLayers, outerIP, outerUDP, gopacket.Payload(vxlanPayload))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		outerLayers...,
	); err != nil {
		return nil, fmt.Errorf("serialize outer: %w", err)
	}
	data := buf.Bytes()

	// Outer L3 starts after the Ethernet header and the optional VLAN tag; every
	// downstream offset is relative to that, so a VLAN tag shifts them all by 4.
	outerIPStart := ethLen + vlanLen
	// Force the outer UDP checksum to 0 in case gopacket computed one.
	outerUDPStart := outerIPStart + ipv4Len
	outerUDPCsum := outerUDPStart + guest.UDPChecksumFieldOffset
	data[outerUDPCsum] = 0
	data[outerUDPCsum+1] = 0

	vxlanStart := outerUDPStart + udpLen   // 42 (+4 tagged)
	innerEthStart := vxlanStart + vxlanLen // 50 (+4 tagged)
	innerOff := innerEthStart + ethLen     // 64 (inner IPv4, ip mode only)
	info := &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"outer.udp.src": uint64(outerUDPStart),
			"vxlan.start":   uint64(vxlanStart),
			"vxlan.vni":     uint64(vxlanStart + 4), // 24-bit VNI within the VXLAN header
			"inner.start":   uint64(innerEthStart),  // inner Ethernet
		},
	}
	if vlanLen > 0 {
		info.Offsets["vlan.tci"] = uint64(ethLen) // 802.1Q TCI (PCP/DEI/VID) at offset 14
	}
	if p.InnerL2Only {
		// L2-only: just the outer IPv4 header checksum (no inner L3/L4). The outer
		// UDP checksum stays 0 (RFC 7348), so no spec for it.
		info.Checksums = []guest.ChecksumSpec{guest.IPv4UDPChecksumSpecs(uint16(outerIPStart))[0]}
		return info, nil
	}
	info.Offsets["inner.ip.start"] = uint64(innerOff)
	info.Offsets["inner.ip.src"] = uint64(innerOff + 12)
	info.Offsets["inner.ip.dst"] = uint64(innerOff + 16)
	info.Offsets["inner.udp.src"] = uint64(innerOff + ipv4Len)
	info.Checksums = buildChecksumSpecs(uint16(outerIPStart), uint16(innerOff), p.InnerUDPChecksum)
	return info, nil
}

// buildChecksumSpecs returns the checksum specs the data plane recomputes.
//
// Unlike GTP-U, VXLAN leaves the outer UDP checksum 0, so no outer UDP spec is
// emitted. The result is [outer IPv4, inner IPv4] and, when includeInnerUDP is
// true, [outer IPv4, inner IPv4, inner UDP] — the inner UDP spec lets the data
// plane keep the inner UDP checksum correct (e.g. when the inner source port or
// inner source IP is varied).
func buildChecksumSpecs(outerIPOff, innerOff uint16, includeInnerUDP bool) []guest.ChecksumSpec {
	// Reuse the outer IPv4 spec from the shared helper; drop its outer UDP entry.
	outerIPv4 := guest.IPv4UDPChecksumSpecs(outerIPOff)[0]
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
