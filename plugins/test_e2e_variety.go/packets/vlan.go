package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildVLANVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildVLANTaggedPacket(cfg.SrcMAC, cfg.DstMAC, 100, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 68, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 28, HeaderStart: 18, HeaderLen: 20, IPHeaderOffset: 18},
				{ChecksumOffset: 44, HeaderStart: 38, HeaderLen: 0, IPHeaderOffset: 18},
			},
			Weight: 1,
		},
	}
}

func BuildQinQVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildQinQPacket(cfg.SrcMAC, cfg.DstMAC, 100, 200, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["outer_vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["inner_vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 72, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 32, HeaderStart: 22, HeaderLen: 20, IPHeaderOffset: 22},
				{ChecksumOffset: 48, HeaderStart: 42, HeaderLen: 0, IPHeaderOffset: 22},
			},
			Weight: 1,
		},
	}
}

func BuildVLANTaggedPacket(srcMAC, dstMAC [6]byte, vlanID uint16, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
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
		eth, vlan, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize VLAN packet: %w", err)
	}

	// VLAN adds 4 bytes: eth(14) + vlan(4) + ip(20) + udp(8)
	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":  0,
			"eth.src":  6,
			"vlan.id":  14, // VLAN TCI (includes PCP, DEI, VID) - VID is lower 12 bits
			"ip.tos":   19, // 14 + 4 + 1
			"ip.ttl":   26, // 14 + 4 + 8
			"ip.src":   30, // 14 + 4 + 12
			"ip.dst":   34, // 14 + 4 + 16
			"udp.src":  38, // 14 + 4 + 20
			"udp.dst":  40, // 14 + 4 + 22
			"payload":  46, // 14 + 4 + 20 + 8
		},
	}, nil
}

func BuildQinQPacket(srcMAC, dstMAC [6]byte, outerVLAN, innerVLAN uint16, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeQinQ,
	}
	outerVlanLayer := &layers.Dot1Q{
		VLANIdentifier: outerVLAN,
		Type:           layers.EthernetTypeDot1Q,
	}
	innerVlanLayer := &layers.Dot1Q{
		VLANIdentifier: innerVLAN,
		Type:           layers.EthernetTypeIPv4,
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
		eth, outerVlanLayer, innerVlanLayer, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize QinQ packet: %w", err)
	}

	// QinQ adds 8 bytes: eth(14) + outer_vlan(4) + inner_vlan(4) + ip(20) + udp(8)
	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":       0,
			"eth.src":       6,
			"outer_vlan.id": 14, // Outer VLAN TCI
			"inner_vlan.id": 18, // Inner VLAN TCI
			"ip.tos":        23, // 14 + 8 + 1
			"ip.ttl":        30, // 14 + 8 + 8
			"ip.src":        34, // 14 + 8 + 12
			"ip.dst":        38, // 14 + 8 + 16
			"udp.src":       42, // 14 + 8 + 20
			"udp.dst":       44, // 14 + 8 + 22
			"payload":       50, // 14 + 8 + 20 + 8
		},
	}, nil
}
