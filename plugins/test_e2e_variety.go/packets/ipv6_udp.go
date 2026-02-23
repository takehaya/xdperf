package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildIPv6UDPVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildIPv6UDPPacket(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIPv6, cfg.DstIPv6, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["ip6.hoplimit"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 32, End: 128}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["ip6.src"] + 8, ByteSize: 8, ByteRange: guest.TemplateRange{Start: 1, End: 255}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 78, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 60, HeaderStart: 54, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

func BuildIPv6UDPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
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
		NextHeader: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip6, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	// IPv6 header: 14 (eth) + 40 (ipv6) = 54, UDP at 54
	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":      0,
			"eth.src":      6,
			"ip6.tc":       14, // Traffic class (partially at byte 14-15)
			"ip6.flow":     15, // Flow label (bytes 15-17, lower 20 bits)
			"ip6.hoplimit": 21,
			"ip6.src":      22,
			"ip6.dst":      38,
			"udp.src":      54,
			"udp.dst":      56,
			"payload":      62,
		},
	}, nil
}
