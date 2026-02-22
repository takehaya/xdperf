package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// BuildICMPv4Variant builds an ICMPv4 Echo Request packet variant for testing
func BuildICMPv4Variant(cfg VariantConfig) VariantResult {
	payload := cfg.Payload
	if len(payload) > 56 {
		payload = payload[:56]
	}
	pkt, err := BuildICMPv4Packet(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIP, cfg.DstIP, 8, 0, payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// ICMPv4 Echo Request offsets: Ethernet(14) + IPv4(20) = 34
	// ICMPv4 Echo: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) + data
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["icmp.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["icmp.seq"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 128}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14},
				{ChecksumOffset: 36, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

// BuildICMPv6Variant builds an ICMPv6 Echo Request packet variant for testing
func BuildICMPv6Variant(cfg VariantConfig) VariantResult {
	payload := cfg.Payload
	if len(payload) > 56 {
		payload = payload[:56]
	}
	pkt, err := BuildICMPv6EchoPacket(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIPv6, cfg.DstIPv6, 1, 1, payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// ICMPv6 Echo Request offsets: Ethernet(14) + IPv6(40) = 54
	// ICMPv6 Echo: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) + data
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["icmp6.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["icmp6.seq"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 78, End: 128}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 56, HeaderStart: 54, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

// BuildICMPv4Packet creates an ICMPv4 packet
func BuildICMPv4Packet(srcMAC, dstMAC [6]byte, srcIP, dstIP string, icmpType, icmpCode uint8, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
		Id:       1,
		Seq:      1,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip4, icmp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize ICMPv4 packet: %w", err)
	}

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":   0,
			"eth.src":   6,
			"ip.src":    26,
			"ip.dst":    30,
			"icmp.type": 34,
			"icmp.code": 35,
			"icmp.id":   38,
			"icmp.seq":  40,
			"payload":   42,
		},
	}, nil
}

// BuildICMPv6Packet creates an ICMPv6 packet
func BuildICMPv6Packet(srcMAC, dstMAC [6]byte, srcIP, dstIP string, icmpType, icmpCode uint8, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		NextHeader: layers.IPProtocolICMPv6,
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(icmpType, icmpCode),
	}
	icmp.SetNetworkLayerForChecksum(ip6)

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip6, icmp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize ICMPv6 packet: %w", err)
	}

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":    0,
			"eth.src":    6,
			"ip6.src":    22,
			"ip6.dst":    38,
			"icmp6.type": 54,
			"icmp6.code": 55,
			"payload":    58,
		},
	}, nil
}

// BuildICMPv6EchoPacket creates an ICMPv6 Echo Request packet with proper structure
func BuildICMPv6EchoPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, id, seq uint16, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		NextHeader: layers.IPProtocolICMPv6,
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(128, 0), // Echo Request
	}
	icmp.SetNetworkLayerForChecksum(ip6)

	echo := &layers.ICMPv6Echo{
		Identifier: id,
		SeqNumber:  seq,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip6, icmp, echo, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize ICMPv6 Echo packet: %w", err)
	}

	// ICMPv6 Echo Request structure:
	// Ethernet(14) + IPv6(40) + ICMPv6(4) + Echo(4) + Payload
	// Offsets: type=54, code=55, checksum=56-57, id=58-59, seq=60-61, payload=62+
	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":    0,
			"eth.src":    6,
			"ip6.src":    22,
			"ip6.dst":    38,
			"icmp6.type": 54,
			"icmp6.code": 55,
			"icmp6.id":   58,
			"icmp6.seq":  60,
			"payload":    62,
		},
	}, nil
}
