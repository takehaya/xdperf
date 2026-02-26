package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// Structure: Eth | IPv6 | SRH | Inner Eth | Inner IP | UDP
func BuildL2VPNSRv6Variant(cfg VariantConfig) VariantResult {
	segments := []string{"2001:db8:1::1", "2001:db8:2::1"}
	innerSrcMAC := [6]byte{0xA2, 0x00, 0x00, 0x00, 0x00, 0x01}
	innerDstMAC := [6]byte{0xA2, 0x00, 0x00, 0x00, 0x00, 0x02}

	pkt, err := BuildL2VPNSRv6Packet(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIPv6, cfg.DstIPv6, segments,
		innerSrcMAC, innerDstMAC, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// Minimum packet: headers = Eth(14) + IPv6(40) + SRH(40) + InnerEth(14) + InnerIP(20) + UDP(8) = 136
	// Use 150 to have some payload
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 150, End: 1514}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: uint16(pkt.Offsets["ip.checksum"]), HeaderStart: uint16(pkt.Offsets["inner_ip"]), HeaderLen: 20, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
				{ChecksumOffset: uint16(pkt.Offsets["udp.checksum"]), HeaderStart: uint16(pkt.Offsets["udp.src"]), HeaderLen: 0, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
			},
			Weight: 1,
		},
	}
}

// Structure: Eth | IPv6 | SRH | Inner IP | UDP
func BuildL3VPNSRv6Variant(cfg VariantConfig) VariantResult {
	segments := []string{"2001:db8:1::1", "2001:db8:2::1"}

	pkt, err := BuildL3VPNSRv6Packet(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIPv6, cfg.DstIPv6, segments,
		cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// Minimum packet: headers = Eth(14) + IPv6(40) + SRH(40) + InnerIP(20) + UDP(8) = 122
	// Use 136 to have some payload
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 136, End: 1514}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: uint16(pkt.Offsets["ip.checksum"]), HeaderStart: uint16(pkt.Offsets["inner_ip"]), HeaderLen: 20, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
				{ChecksumOffset: uint16(pkt.Offsets["udp.checksum"]), HeaderStart: uint16(pkt.Offsets["udp.src"]), HeaderLen: 0, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
			},
			Weight: 1,
		},
	}
}

func BuildL2VPNSRv6Packet(srcMAC, dstMAC [6]byte, outerSrcIP, outerDstIP string, segments []string,
	innerSrcMAC, innerDstMAC [6]byte, innerSrcIP, innerDstIP string,
	srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {

	if len(segments) == 0 {
		return nil, fmt.Errorf("at least one segment is required")
	}

	// Parse segment addresses
	segmentIPs := make([]net.IP, len(segments))
	for i, seg := range segments {
		ip := net.ParseIP(seg)
		if ip == nil {
			return nil, fmt.Errorf("invalid segment address: %s", seg)
		}
		segmentIPs[i] = ip.To16()
	}

	srhLen := 8 + len(segments)*16
	hdrExtLen := uint8((srhLen / 8) - 1)

	// Build inner packet first
	innerBuf := gopacket.NewSerializeBuffer()
	innerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(innerSrcMAC[:]),
		DstMAC:       net.HardwareAddr(innerDstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	innerIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(innerSrcIP),
		DstIP:    net.ParseIP(innerDstIP),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(innerBuf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		innerEth, innerIP, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize inner packet: %w", err)
	}
	innerPacket := innerBuf.Bytes()

	// Build outer packet
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(outerSrcIP),
		DstIP:      net.ParseIP(outerDstIP),
		NextHeader: layers.IPProtocolIPv6Routing, // 43
	}

	// SRH with Ethernet as inner protocol (use raw protocol number)
	srh := &SRv6Layer{
		NextHeader:   143, // Ethernet (RFC 8986)
		HdrExtLen:    hdrExtLen,
		RoutingType:  4,
		SegmentsLeft: uint8(len(segments) - 1),
		LastEntry:    uint8(len(segments) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentIPs,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip6, srh, gopacket.Payload(innerPacket)); err != nil {
		return nil, fmt.Errorf("failed to serialize L2VPN SRv6 packet: %w", err)
	}

	// Fix IPv6 payload length
	data := buf.Bytes()
	payloadLen := uint16(len(data) - 54) // Everything after IPv6 header
	binary.BigEndian.PutUint16(data[18:20], payloadLen)

	// Calculate offsets
	srhOffset := uint64(54)
	innerEthOffset := srhOffset + uint64(srhLen)
	innerIPOffset := innerEthOffset + 14
	udpOffset := innerIPOffset + 20

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":         0,
			"eth.src":         6,
			"ip6.src":         22,
			"ip6.dst":         38,
			"srh":             srhOffset,
			"inner_eth.dst":   innerEthOffset,
			"inner_eth.src":   innerEthOffset + 6,
			"inner_ip":        innerIPOffset,
			"ip.checksum":     innerIPOffset + 10,
			"ip.src":          innerIPOffset + 12,
			"ip.dst":          innerIPOffset + 16,
			"udp.src":         udpOffset,
			"udp.dst":         udpOffset + 2,
			"udp.checksum":    udpOffset + 6,
			"payload":         udpOffset + 8,
		},
	}, nil
}

func BuildL3VPNSRv6Packet(srcMAC, dstMAC [6]byte, outerSrcIP, outerDstIP string, segments []string,
	innerSrcIP, innerDstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {

	if len(segments) == 0 {
		return nil, fmt.Errorf("at least one segment is required")
	}

	// Parse segment addresses
	segmentIPs := make([]net.IP, len(segments))
	for i, seg := range segments {
		ip := net.ParseIP(seg)
		if ip == nil {
			return nil, fmt.Errorf("invalid segment address: %s", seg)
		}
		segmentIPs[i] = ip.To16()
	}

	srhLen := 8 + len(segments)*16
	hdrExtLen := uint8((srhLen / 8) - 1)

	// Build inner packet first
	innerBuf := gopacket.NewSerializeBuffer()
	innerIP := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(innerSrcIP),
		DstIP:    net.ParseIP(innerDstIP),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(innerBuf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		innerIP, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize inner packet: %w", err)
	}
	innerPacket := innerBuf.Bytes()

	// Build outer packet
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(outerSrcIP),
		DstIP:      net.ParseIP(outerDstIP),
		NextHeader: layers.IPProtocolIPv6Routing, // 43
	}

	// SRH with IPv4 as inner protocol
	srh := &SRv6Layer{
		NextHeader:   4, // IPv4 (IPIP)
		HdrExtLen:    hdrExtLen,
		RoutingType:  4,
		SegmentsLeft: uint8(len(segments) - 1),
		LastEntry:    uint8(len(segments) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentIPs,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip6, srh, gopacket.Payload(innerPacket)); err != nil {
		return nil, fmt.Errorf("failed to serialize L3VPN SRv6 packet: %w", err)
	}

	// Fix IPv6 payload length
	data := buf.Bytes()
	payloadLen := uint16(len(data) - 54)
	binary.BigEndian.PutUint16(data[18:20], payloadLen)

	// Calculate offsets
	srhOffset := uint64(54)
	innerIPOffset := srhOffset + uint64(srhLen)
	udpOffset := innerIPOffset + 20

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":      0,
			"eth.src":      6,
			"ip6.src":      22,
			"ip6.dst":      38,
			"srh":          srhOffset,
			"inner_ip":     innerIPOffset,
			"ip.checksum":  innerIPOffset + 10,
			"ip.src":       innerIPOffset + 12,
			"ip.dst":       innerIPOffset + 16,
			"udp.src":      udpOffset,
			"udp.dst":      udpOffset + 2,
			"udp.checksum": udpOffset + 6,
			"payload":      udpOffset + 8,
		},
	}, nil
}

// SRv6Layer is a custom serializable SRv6 Segment Routing Header
type SRv6Layer struct {
	layers.BaseLayer
	NextHeader   uint8
	HdrExtLen    uint8
	RoutingType  uint8
	SegmentsLeft uint8
	LastEntry    uint8
	Flags        uint8
	Tag          uint16
	Segments     []net.IP
}

func (s *SRv6Layer) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (s *SRv6Layer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	srhLen := 8 + len(s.Segments)*16
	bytes, err := b.PrependBytes(srhLen)
	if err != nil {
		return err
	}

	bytes[0] = s.NextHeader
	bytes[1] = s.HdrExtLen
	bytes[2] = s.RoutingType
	bytes[3] = s.SegmentsLeft
	bytes[4] = s.LastEntry
	bytes[5] = s.Flags
	binary.BigEndian.PutUint16(bytes[6:8], s.Tag)

	offset := 8
	for i := len(s.Segments) - 1; i >= 0; i-- {
		ip := s.Segments[i].To16()
		if ip == nil {
			ip = make([]byte, 16)
		}
		copy(bytes[offset:offset+16], ip)
		offset += 16
	}

	return nil
}
