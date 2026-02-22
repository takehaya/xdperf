package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// BuildL2VPNVariant builds an L2VPN (MPLS with inner Ethernet) packet variant
// Structure: Eth | MPLS(Transport) | MPLS(VPN) | Inner Eth | Inner IP | UDP
func BuildL2VPNVariant(cfg VariantConfig) VariantResult {
	// Inner MAC addresses (customer MACs)
	innerSrcMAC := [6]byte{0xA2, 0x00, 0x00, 0x00, 0x00, 0x01}
	innerDstMAC := [6]byte{0xA2, 0x00, 0x00, 0x00, 0x00, 0x02}

	pkt, err := BuildL2VPNPacket(cfg.SrcMAC, cfg.DstMAC, 1000, 2000,
		innerSrcMAC, innerDstMAC, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// Offsets: Eth(14) + MPLS(4) + MPLS(4) + InnerEth(14) + IP(20) + UDP(8)
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 80, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: uint16(pkt.Offsets["ip.checksum"]), HeaderStart: uint16(pkt.Offsets["inner_ip"]), HeaderLen: 20, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
				{ChecksumOffset: uint16(pkt.Offsets["udp.checksum"]), HeaderStart: uint16(pkt.Offsets["udp.src"]), HeaderLen: 0, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
			},
			Weight: 1,
		},
	}
}

// BuildL3VPNVariant builds an L3VPN (MPLS with inner IP) packet variant
// Structure: Eth | MPLS(Transport) | MPLS(VPN) | Inner IP | UDP
func BuildL3VPNVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildL3VPNPacket(cfg.SrcMAC, cfg.DstMAC, 1000, 2000,
		cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// Offsets: Eth(14) + MPLS(4) + MPLS(4) + IP(20) + UDP(8)
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 66, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: uint16(pkt.Offsets["ip.checksum"]), HeaderStart: uint16(pkt.Offsets["inner_ip"]), HeaderLen: 20, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
				{ChecksumOffset: uint16(pkt.Offsets["udp.checksum"]), HeaderStart: uint16(pkt.Offsets["udp.src"]), HeaderLen: 0, IPHeaderOffset: uint16(pkt.Offsets["inner_ip"])},
			},
			Weight: 1,
		},
	}
}

// BuildL2VPNSRv6Variant builds an L2VPN over SRv6 packet variant
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

// BuildL3VPNSRv6Variant builds an L3VPN over SRv6 packet variant
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

// BuildL2VPNPacket creates an L2VPN packet (MPLS with inner Ethernet)
func BuildL2VPNPacket(srcMAC, dstMAC [6]byte, transportLabel, vpnLabel uint32,
	innerSrcMAC, innerDstMAC [6]byte, innerSrcIP, innerDstIP string,
	srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {

	buf := gopacket.NewSerializeBuffer()

	// Outer Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeMPLSUnicast,
	}

	// Transport label (outer)
	mplsTransport := &layers.MPLS{
		Label:       transportLabel,
		TTL:         64,
		StackBottom: false,
	}

	// VPN label (bottom of stack)
	mplsVPN := &layers.MPLS{
		Label:       vpnLabel,
		TTL:         64,
		StackBottom: true,
	}

	// Inner Ethernet
	innerEth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(innerSrcMAC[:]),
		DstMAC:       net.HardwareAddr(innerDstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Inner IP
	ip4 := &layers.IPv4{
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
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, mplsTransport, mplsVPN, innerEth, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize L2VPN packet: %w", err)
	}

	// Offsets: Eth(14) + MPLS(4) + MPLS(4) + InnerEth(14) + IP(20) + UDP(8)
	innerEthOffset := uint64(22)  // 14 + 4 + 4
	innerIPOffset := uint64(36)   // 22 + 14
	udpOffset := uint64(56)       // 36 + 20

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":       0,
			"eth.src":       6,
			"mpls.transport": 14,
			"mpls.vpn":       18,
			"inner_eth.dst":  innerEthOffset,
			"inner_eth.src":  innerEthOffset + 6,
			"inner_ip":       innerIPOffset,
			"ip.checksum":    innerIPOffset + 10,
			"ip.src":         innerIPOffset + 12,
			"ip.dst":         innerIPOffset + 16,
			"udp.src":        udpOffset,
			"udp.dst":        udpOffset + 2,
			"udp.checksum":   udpOffset + 6,
			"payload":        udpOffset + 8,
		},
	}, nil
}

// BuildL3VPNPacket creates an L3VPN packet (MPLS with inner IP, no inner Ethernet)
func BuildL3VPNPacket(srcMAC, dstMAC [6]byte, transportLabel, vpnLabel uint32,
	innerSrcIP, innerDstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {

	buf := gopacket.NewSerializeBuffer()

	// Outer Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeMPLSUnicast,
	}

	// Transport label (outer)
	mplsTransport := &layers.MPLS{
		Label:       transportLabel,
		TTL:         64,
		StackBottom: false,
	}

	// VPN label (bottom of stack)
	mplsVPN := &layers.MPLS{
		Label:       vpnLabel,
		TTL:         64,
		StackBottom: true,
	}

	// Inner IP (no inner Ethernet)
	ip4 := &layers.IPv4{
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
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, mplsTransport, mplsVPN, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize L3VPN packet: %w", err)
	}

	// Offsets: Eth(14) + MPLS(4) + MPLS(4) + IP(20) + UDP(8)
	innerIPOffset := uint64(22)  // 14 + 4 + 4
	udpOffset := uint64(42)      // 22 + 20

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":        0,
			"eth.src":        6,
			"mpls.transport": 14,
			"mpls.vpn":       18,
			"inner_ip":       innerIPOffset,
			"ip.checksum":    innerIPOffset + 10,
			"ip.src":         innerIPOffset + 12,
			"ip.dst":         innerIPOffset + 16,
			"udp.src":        udpOffset,
			"udp.dst":        udpOffset + 2,
			"udp.checksum":   udpOffset + 6,
			"payload":        udpOffset + 8,
		},
	}, nil
}

// BuildL2VPNSRv6Packet creates an L2VPN over SRv6 packet
// Structure: Eth(14) | IPv6(40) | SRH(8+16*n) | Inner Eth(14) | Inner IP(20) | UDP(8) | Payload
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
	srh := &SRv6LayerWithEthernet{
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

// BuildL3VPNSRv6Packet creates an L3VPN over SRv6 packet
// Structure: Eth(14) | IPv6(40) | SRH(8+16*n) | Inner IP(20) | UDP(8) | Payload
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
	srh := &SRv6LayerWithEthernet{
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

// SRv6LayerWithEthernet is similar to SRv6Layer but allows any NextHeader
type SRv6LayerWithEthernet struct {
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

func (s *SRv6LayerWithEthernet) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (s *SRv6LayerWithEthernet) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
