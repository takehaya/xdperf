package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// BuildIPv4UDPVariant builds an IPv4 UDP packet variant for testing
func BuildIPv4UDPVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildIPv4UDPPacket(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["ip.ttl"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 64, End: 128}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["ip.tos"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 63}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["ip.src"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0xC0A80101, End: 0xC0A801FE}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["eth.dst"], ByteSize: 6, ByteRange: guest.TemplateRange{Start: 0x001122334455, End: 0x0011223344FF}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["payload"] + 1, ByteSize: 8, ByteRange: guest.TemplateRange{Start: 1, End: 255}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14},
				{ChecksumOffset: 40, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

// BuildIPv4UDPPacket creates an IPv4 UDP packet
func BuildIPv4UDPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
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
		eth, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":  0,
			"eth.src":  6,
			"ip.tos":   15,
			"ip.id":    18,
			"ip.ttl":   22,
			"ip.src":   26,
			"ip.dst":   30,
			"udp.src":  34,
			"udp.dst":  36,
			"payload":  42,
		},
	}, nil
}

// BuildIPv4WithOptionsPacket creates an IPv4 packet with IP options
func BuildIPv4WithOptionsPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, options []byte, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Pad options to 4-byte boundary
	optLen := len(options)
	paddedOptLen := ((optLen + 3) / 4) * 4
	paddedOptions := make([]byte, paddedOptLen)
	copy(paddedOptions, options)

	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      uint8(5 + paddedOptLen/4),
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolUDP,
		Options:  []layers.IPv4Option{{OptionType: 0, OptionLength: uint8(paddedOptLen), OptionData: paddedOptions}},
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize IPv4 with options packet: %w", err)
	}

	ipHeaderLen := 20 + paddedOptLen

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":    0,
			"eth.src":    6,
			"ip.tos":     15,
			"ip.ttl":     22,
			"ip.src":     26,
			"ip.dst":     30,
			"ip.options": 34, // Start of IP options
			"udp.src":    uint64(14 + ipHeaderLen),
			"udp.dst":    uint64(14 + ipHeaderLen + 2),
			"payload":    uint64(14 + ipHeaderLen + 8),
		},
	}, nil
}
