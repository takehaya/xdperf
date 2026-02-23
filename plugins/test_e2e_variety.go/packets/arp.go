package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildARPVariant(cfg VariantConfig) VariantResult {
	pkt, err := BuildARPPacket(cfg.SrcMAC, cfg.SrcIP, cfg.DstIP, uint16(layers.ARPRequest))
	if err != nil {
		return VariantResult{Err: err}
	}

	// ARP has no checksum, only vary sender IP
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["arp.sender_ip"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0, End: 0xFFFFFFFF}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // ARP has no checksum
			Weight:    1,
		},
	}
}

func BuildARPPacket(srcMAC [6]byte, senderIP, targetIP string, operation uint16) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	// ARP broadcast
	dstMAC := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         operation,
		SourceHwAddress:   srcMAC[:],
		SourceProtAddress: net.ParseIP(senderIP).To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(targetIP).To4(),
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, arp); err != nil {
		return nil, fmt.Errorf("failed to serialize ARP packet: %w", err)
	}

	// Pad to minimum xdperf frame size (64 bytes)
	data := buf.Bytes()
	if len(data) < 64 {
		padded := make([]byte, 64)
		copy(padded, data)
		data = padded
	}

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":        0,
			"eth.src":        6,
			"arp.op":         20, // Operation field (2 bytes)
			"arp.sender_mac": 22, // Sender hardware address (6 bytes)
			"arp.sender_ip":  28, // Sender protocol address (4 bytes)
			"arp.target_mac": 32, // Target hardware address (6 bytes)
			"arp.target_ip":  38, // Target protocol address (4 bytes)
		},
	}, nil
}
