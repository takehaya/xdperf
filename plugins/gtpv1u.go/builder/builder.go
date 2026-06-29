// Package builder constructs GTPv1-U (G-PDU) base packets and their checksum
// specs. It deliberately depends only on gopacket and the host-compatible parts
// of pkg/guest (types + IPv4UDPChecksumSpecs), never on the wasm-only goshim /
// host-import surface, so it can be unit tested with a plain `go test` on the
// host.
//
// The GTP-U header is assembled as raw bytes (full control over offsets, the PSC
// extension header, and the Message Length field) and concatenated with a
// separately serialized inner IPv4/UDP packet. gopacket then serializes the
// outer Ethernet/IPv4/UDP around that payload. We do NOT use gopacket's built-in
// GTPv1U layer: its SerializeTo appends the optional/extension bytes to the end
// of the buffer (after the inner payload), which is wrong for a tunnel.
package builder

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// GTPUPort is the well-known GTP-U UDP destination port.
const GTPUPort = 2152

// Fixed layer sizes used to derive offsets.
const (
	ethLen      = guest.EthernetHeaderLen // 14
	ipv4Len     = guest.IPv4HeaderLen     // 20
	udpLen      = guest.UDPHeaderLen      // 8
	gtpMandLen  = 8                       // mandatory GTP-U header
	gtpOptLen   = 4                       // seq + npdu + next-ext-type
	gtpPSCLen   = 4                       // PDU Session Container extension header
	innerL4Over = ipv4Len + udpLen        // inner IPv4 + UDP (ICMP echo header is also 8 bytes)
)

// PacketParams fully describes one GTP-U frame to build. main.go fills this from
// the JSON GeneratorRequest; the builder stays free of JSON/default concerns.
type PacketParams struct {
	SrcMAC, DstMAC [6]byte
	SrcIP, DstIP   string
	OuterSrcPort   uint16

	TEID      uint32
	EnablePSC bool
	EnableSeq bool
	SeqNum    uint16
	PDUTypeUL bool // false = downlink (DL), true = uplink (UL)
	RQI       bool
	QFI       uint8

	InnerSrcIP, InnerDstIP     string
	InnerSrcPort, InnerDstPort uint16
	// InnerProto selects the inner (T-PDU) transport: "udp" (default) or "icmp"
	// (an ICMPv4 echo request). Empty is treated as "udp".
	InnerProto string
	// InnerUDPChecksum, when false (the default), leaves the inner UDP checksum 0
	// (disabled — legal over IPv4) and emits no inner UDP checksum spec, so the
	// data plane never touches it. When true the checksum is computed and a spec
	// is emitted so the data plane keeps it correct. ICMP ignores this field.
	InnerUDPChecksum bool
}

// innerIsICMP reports whether the inner T-PDU should be an ICMPv4 echo request.
func (p *PacketParams) innerIsICMP() bool {
	return strings.EqualFold(p.InnerProto, "icmp")
}

// PacketInfo is the built base packet plus named byte offsets used to drive
// VariableParams and ChecksumSpec construction.
type PacketInfo struct {
	Data      []byte
	Offsets   map[string]uint64
	Checksums []guest.ChecksumSpec
}

// gtpHeaderLen returns the GTP-U header length implied by the flags.
func (p *PacketParams) gtpHeaderLen() int {
	n := gtpMandLen
	if p.EnablePSC || p.EnableSeq {
		n += gtpOptLen
	}
	if p.EnablePSC {
		n += gtpPSCLen
	}
	return n
}

// MinFrameLen is the smallest total frame length (including Ethernet) that can
// hold all headers with a zero-length inner payload.
func MinFrameLen(p PacketParams) int {
	return ethLen + ipv4Len + udpLen + p.gtpHeaderLen() + innerL4Over
}

// buildGTPHeader assembles the raw GTP-U header bytes. innerLen is the byte
// length of everything that follows the GTP-U header (the inner IP packet), used
// to fill the Message Length field.
func buildGTPHeader(p *PacketParams, innerLen int) []byte {
	hasOpt := p.EnablePSC || p.EnableSeq

	flags := byte(0x30) // Version 1 (bits 7-5 = 001) + PT 1 (bit 4)
	if p.EnablePSC {
		flags |= 0x04 // E: extension header present
	}
	if p.EnableSeq {
		flags |= 0x02 // S: sequence number present
	}

	extra := 0
	if hasOpt {
		extra += gtpOptLen
	}
	if p.EnablePSC {
		extra += gtpPSCLen
	}

	// Message Length counts everything after the mandatory 8 octets.
	msgLen := extra + innerLen

	h := make([]byte, gtpMandLen+extra)
	h[0] = flags
	h[1] = 0xFF // message type: G-PDU
	binary.BigEndian.PutUint16(h[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(h[4:8], p.TEID)

	if hasOpt {
		binary.BigEndian.PutUint16(h[8:10], p.SeqNum) // sequence number
		h[10] = 0                                     // N-PDU number
		nextExt := byte(0x00)
		if p.EnablePSC {
			nextExt = 0x85 // PDU Session Container
		}
		h[11] = nextExt

		if p.EnablePSC {
			// PDU Session Container extension header (4 octets, len=1 unit).
			h[12] = 0x01 // extension header length in 4-octet units
			pscB1 := byte(0x00)
			if p.PDUTypeUL {
				pscB1 = 0x10 // PDU Type 1 (UL) in the high nibble
			}
			h[13] = pscB1
			qfiByte := p.QFI & 0x3F
			// RQI (Reflective QoS Indicator) is a downlink-only field: it lives in
			// PSC octet 2 bit 7 of DL PDU Session Information. In the UL frame that
			// bit is spare, so RQI must never be set for an uplink container.
			if p.RQI && !p.PDUTypeUL {
				qfiByte |= 0x40
			}
			h[14] = qfiByte
			h[15] = 0x00 // next extension header type: none (end)
		}
	}
	return h
}

// buildInner serializes the inner IPv4/UDP packet with correct inner IP/UDP
// length fields and checksums.
func buildInner(p *PacketParams, payload []byte) ([]byte, error) {
	innerIP := &layers.IPv4{
		Version: 4,
		IHL:     5,
		TTL:     64,
		SrcIP:   net.ParseIP(p.InnerSrcIP),
		DstIP:   net.ParseIP(p.InnerDstIP),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if p.innerIsICMP() {
		innerIP.Protocol = layers.IPProtocolICMPv4
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       0x1234,
			Seq:      1,
		}
		if err := gopacket.SerializeLayers(buf, opts, innerIP, icmp, gopacket.Payload(payload)); err != nil {
			return nil, fmt.Errorf("serialize inner ICMPv4: %w", err)
		}
		return buf.Bytes(), nil
	}

	innerIP.Protocol = layers.IPProtocolUDP
	innerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.InnerSrcPort),
		DstPort: layers.UDPPort(p.InnerDstPort),
	}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("inner SetNetworkLayerForChecksum: %w", err)
	}
	if err := gopacket.SerializeLayers(buf, opts, innerIP, innerUDP, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize inner UDP: %w", err)
	}
	out := buf.Bytes()
	if !p.InnerUDPChecksum {
		// A zero UDP checksum is legal over IPv4 and means "not computed". With no
		// inner UDP checksum spec either, the data plane never writes this field,
		// so it cannot be left stale by the multi-variant (IMIX) base-reuse path.
		csumOff := ipv4Len + guest.UDPChecksumFieldOffset // 26
		out[csumOff] = 0
		out[csumOff+1] = 0
	}
	return out, nil
}

// BuildGTPv1UPacket builds a single GTP-U frame of exactly totalLen bytes (the
// on-wire length including the 14-byte Ethernet header, excluding FCS).
func BuildGTPv1UPacket(p PacketParams, totalLen int) (*PacketInfo, error) {
	minLen := MinFrameLen(p)
	if totalLen < minLen {
		return nil, fmt.Errorf("totalLen %d is smaller than the minimum GTP-U frame length %d", totalLen, minLen)
	}
	payloadLen := totalLen - minLen
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	innerBytes, err := buildInner(&p, payload)
	if err != nil {
		return nil, err
	}
	gtpHeader := buildGTPHeader(&p, len(innerBytes))
	gtpPayload := make([]byte, 0, len(gtpHeader)+len(innerBytes))
	gtpPayload = append(gtpPayload, gtpHeader...)
	gtpPayload = append(gtpPayload, innerBytes...)

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
		DstPort: layers.UDPPort(GTPUPort),
	}
	if err := outerUDP.SetNetworkLayerForChecksum(outerIP); err != nil {
		return nil, fmt.Errorf("outer SetNetworkLayerForChecksum: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, outerIP, outerUDP, gopacket.Payload(gtpPayload),
	); err != nil {
		return nil, fmt.Errorf("serialize outer: %w", err)
	}

	gtpStart := ethLen + ipv4Len + udpLen // 42
	innerOff := gtpStart + len(gtpHeader)
	info := &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"gtp.start":    uint64(gtpStart),
			"gtp.teid":     uint64(gtpStart + 4),
			"inner.start":  uint64(innerOff),
			"inner.ip.src": uint64(innerOff + 12),
		},
	}
	if p.innerIsICMP() {
		info.Offsets["inner.icmp.id"] = uint64(innerOff + ipv4Len + 4)
		info.Offsets["inner.icmp.seq"] = uint64(innerOff + ipv4Len + 6)
	} else {
		info.Offsets["inner.udp.src"] = uint64(innerOff + ipv4Len)
	}
	if p.EnablePSC {
		// QFI lives in the second content octet of the PSC extension header:
		// gtpStart + mandatory(8) + optional(4) + extLen(1) + pscOctet1(1).
		info.Offsets["psc.qfi"] = uint64(gtpStart + gtpMandLen + gtpOptLen + 2)
	}
	includeInnerUDP := !p.innerIsICMP() && p.InnerUDPChecksum
	info.Checksums = buildChecksumSpecs(uint16(innerOff), includeInnerUDP)
	return info, nil
}

// buildChecksumSpecs returns the checksum specs in the order the data plane must
// process them: the outer UDP checksum covers the inner bytes, so it is always
// recomputed last.
//
// When includeInnerUDP is true the result is [outer IPv4, inner IPv4, inner UDP,
// outer UDP] — the inner UDP spec lets the data plane keep the inner UDP checksum
// correct (e.g. when the inner source port is varied).
//
// Otherwise it is [outer IPv4, inner IPv4, outer UDP]. This is used for inner
// ICMP (its message is static, gopacket's baked-in checksum is authoritative,
// and the data plane miscomputes ICMPv4) and for inner UDP with the checksum
// disabled (the field is 0 and must stay untouched). The outer UDP checksum
// still covers and protects the inner bytes.
func buildChecksumSpecs(innerOff uint16, includeInnerUDP bool) []guest.ChecksumSpec {
	outer := guest.IPv4UDPChecksumSpecs(ethLen) // [outer IPv4, outer UDP]
	innerIP := guest.ChecksumSpec{
		ChecksumOffset: innerOff + guest.IPv4ChecksumFieldOffset,
		HeaderStart:    innerOff,
		HeaderLen:      guest.IPv4HeaderLen,
		IPHeaderOffset: innerOff,
	}
	if !includeInnerUDP {
		return []guest.ChecksumSpec{outer[0], innerIP, outer[1]}
	}
	innerUDPStart := innerOff + ipv4Len
	innerUDP := guest.ChecksumSpec{
		ChecksumOffset: innerUDPStart + guest.UDPChecksumFieldOffset,
		HeaderStart:    innerUDPStart,
		HeaderLen:      0, // 0 = derive length from the inner IPv4 total length
		IPHeaderOffset: innerOff,
	}
	return []guest.ChecksumSpec{outer[0], innerIP, innerUDP, outer[1]}
}
