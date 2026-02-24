package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

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
