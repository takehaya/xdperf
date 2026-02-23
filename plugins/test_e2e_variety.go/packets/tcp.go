package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildTCPVariant(cfg VariantConfig) VariantResult {
	// SYN packet with no payload (standard TCP handshake)
	pkt, err := BuildTCPPacket(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIP, cfg.DstIP, cfg.SrcPort, cfg.DstPort, 0x02, nil)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["tcp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["tcp.seq"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 1, End: 0xFFFFFFFF}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14},
				{ChecksumOffset: 50, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

func BuildTCPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, flags uint8, payload []byte) (*PacketInfo, error) {
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
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		Window:  65535,
		SYN:     flags&0x02 != 0,
		ACK:     flags&0x10 != 0,
		FIN:     flags&0x01 != 0,
		RST:     flags&0x04 != 0,
		PSH:     flags&0x08 != 0,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip4, tcp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize TCP packet: %w", err)
	}

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":   0,
			"eth.src":   6,
			"ip.src":    26,
			"ip.dst":    30,
			"tcp.src":   34,
			"tcp.dst":   36,
			"tcp.seq":   38,
			"tcp.flags": 47, // Flags byte in TCP header
			"payload":   54, // Assuming no TCP options
		},
	}, nil
}
