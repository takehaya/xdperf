package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

// Note: MPLS label field is 20 bits within 4 bytes, mixed with Exp(3), S(1), TTL(8).
// Varying the label safely requires preserving S=1 and TTL. For simplicity, we only
// vary the first 2 bytes of the label (upper 16 bits of 20-bit label) and UDP src port.
func BuildMPLSVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildMPLSPacket(cfg.SrcMAC, cfg.DstMAC, 1000, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// MPLS header at offset 14: Label(20) | Exp(3) | S(1) | TTL(8)
	// Bytes: [Label[19:12]] [Label[11:4]] [Label[3:0],Exp,S] [TTL]
	// Only vary first 2 bytes (Label[19:4]) to keep S=1 and TTL intact
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["mpls.label"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 0, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
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

func BuildMPLSStackVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildMPLSStackPacket(cfg.SrcMAC, cfg.DstMAC, []uint32{1000, 2000, 3000}, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 76, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 36, HeaderStart: 26, HeaderLen: 20, IPHeaderOffset: 26},
				{ChecksumOffset: 52, HeaderStart: 46, HeaderLen: 0, IPHeaderOffset: 26},
			},
			Weight: 1,
		},
	}
}

func BuildMPLSPacket(srcMAC, dstMAC [6]byte, label uint32, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeMPLSUnicast,
	}
	mpls := &layers.MPLS{
		Label:       label,
		TTL:         64,
		StackBottom: true,
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
		eth, mpls, ip4, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize MPLS packet: %w", err)
	}

	// MPLS adds 4 bytes: eth(14) + mpls(4) + ip(20) + udp(8)
	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":    0,
			"eth.src":    6,
			"mpls.label": 14, // MPLS label (20 bits in upper part of 4-byte field)
			"ip.tos":     19, // 14 + 4 + 1
			"ip.ttl":     26, // 14 + 4 + 8
			"ip.src":     30, // 14 + 4 + 12
			"ip.dst":     34, // 14 + 4 + 16
			"udp.src":    38, // 14 + 4 + 20
			"udp.dst":    40, // 14 + 4 + 22
			"payload":    46, // 14 + 4 + 20 + 8
		},
	}, nil
}

func BuildMPLSStackPacket(srcMAC, dstMAC [6]byte, labels []uint32, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeMPLSUnicast,
	}

	// Build layer list
	layerList := []gopacket.SerializableLayer{eth}

	for i, label := range labels {
		mpls := &layers.MPLS{
			Label:       label,
			TTL:         64,
			StackBottom: i == len(labels)-1,
		}
		layerList = append(layerList, mpls)
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

	layerList = append(layerList, ip4, udp, gopacket.Payload(payload))

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		layerList...); err != nil {
		return nil, fmt.Errorf("failed to serialize MPLS stack packet: %w", err)
	}

	mplsLen := len(labels) * 4
	ipOffset := 14 + mplsLen

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":    0,
			"eth.src":    6,
			"mpls.label": 14, // First MPLS label
			"ip.src":     uint64(ipOffset + 12),
			"ip.dst":     uint64(ipOffset + 16),
			"udp.src":    uint64(ipOffset + 20),
			"udp.dst":    uint64(ipOffset + 22),
			"payload":    uint64(ipOffset + 28),
		},
	}, nil
}
