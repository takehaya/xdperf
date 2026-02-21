package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketInfo contains the built packet and offset information
type PacketInfo struct {
	Data    []byte
	Offsets map[string]uint64 // Named offsets for variable fields
}

// ============================================================
// IPv4 UDP Packet
// ============================================================

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
			"eth.dst":    0,
			"eth.src":    6,
			"ip.tos":     15,
			"ip.id":      18,
			"ip.ttl":     22,
			"ip.src":     26,
			"ip.dst":     30,
			"udp.src":    34,
			"udp.dst":    36,
			"payload":    42,
		},
	}, nil
}

// ============================================================
// IPv6 UDP Packet
// ============================================================

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

// ============================================================
// ARP Packet
// ============================================================

func BuildARPPacket(srcMAC [6]byte, senderIP, targetIP string, operation uint16) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	// ARP broadcast
	dstMAC := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if operation == layers.ARPReply {
		// For reply, we'd normally set a specific MAC, but for testing use broadcast
	}

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

// ============================================================
// VLAN Tagged Packet (802.1Q)
// ============================================================

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

// ============================================================
// QinQ (Double VLAN) Packet
// ============================================================

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

// ============================================================
// MPLS Packet
// ============================================================

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

// BuildMPLSStackPacket creates an MPLS packet with multiple labels
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

// ============================================================
// LLDP Packet
// ============================================================

func BuildLLDPPacket(srcMAC [6]byte, chassisID string, portID string, ttl uint16) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	// LLDP multicast destination
	lldpDstMAC := [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(lldpDstMAC[:]),
		EthernetType: layers.EthernetTypeLinkLayerDiscovery,
	}

	lldp := &layers.LinkLayerDiscovery{
		ChassisID: layers.LLDPChassisID{
			Subtype: layers.LLDPChassisIDSubTypeMACAddr,
			ID:      srcMAC[:],
		},
		PortID: layers.LLDPPortID{
			Subtype: layers.LLDPPortIDSubtypeLocal,
			ID:      []byte(portID),
		},
		TTL: ttl,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, lldp); err != nil {
		return nil, fmt.Errorf("failed to serialize LLDP packet: %w", err)
	}

	// Pad to minimum frame size
	data := buf.Bytes()
	if len(data) < 64 {
		padded := make([]byte, 64)
		copy(padded, data)
		data = padded
	}

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":     0,
			"eth.src":     6,
			"lldp.tlv":    14, // Start of LLDP TLVs
			"lldp.ttl":    14 + 2 + 1 + 6 + 2 + 1 + uint64(len(portID)) + 2, // After chassis ID TLV and port ID TLV
		},
	}, nil
}

// ============================================================
// EAPoL Packet
// ============================================================

func BuildEAPoLPacket(srcMAC, dstMAC [6]byte, eapolType layers.EAPOLType, body []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: layers.EthernetTypeEAPOL,
	}

	eapol := &layers.EAPOL{
		Version: 2,
		Type:    eapolType,
		Length:  uint16(len(body)),
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, eapol, gopacket.Payload(body)); err != nil {
		return nil, fmt.Errorf("failed to serialize EAPoL packet: %w", err)
	}

	// Pad to minimum frame size
	data := buf.Bytes()
	if len(data) < 64 {
		padded := make([]byte, 64)
		copy(padded, data)
		data = padded
	}

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":      0,
			"eth.src":      6,
			"eapol.type":   15, // EAPoL type field
			"eapol.length": 16, // EAPoL length field (2 bytes)
			"eapol.body":   18, // EAPoL body starts here
		},
	}, nil
}

// ============================================================
// IPv4 with Options Packet
// ============================================================

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

// ============================================================
// Raw Ethernet Frame
// ============================================================

func BuildRawEthernetFrame(srcMAC, dstMAC [6]byte, etherType layers.EthernetType, payload []byte) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
		EthernetType: etherType,
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
		eth, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize raw Ethernet frame: %w", err)
	}

	// Pad to minimum frame size
	data := buf.Bytes()
	if len(data) < 64 {
		padded := make([]byte, 64)
		copy(padded, data)
		data = padded
	}

	return &PacketInfo{
		Data: data,
		Offsets: map[string]uint64{
			"eth.dst":     0,
			"eth.src":     6,
			"eth.type":    12,
			"payload":     14,
		},
	}, nil
}

// ============================================================
// ICMPv4 Packet
// ============================================================

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

// ============================================================
// ICMPv6 Packet
// ============================================================

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

// ============================================================
// TCP Packet
// ============================================================

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

// ============================================================
// SRv6 (Segment Routing over IPv6) Packet
// Reference: https://github.com/nttcom/fluvia/blob/main/internal/pkg/meter/srv6.go
// ============================================================

// SRv6Layer represents a Segment Routing Header (SRH) for IPv6
type SRv6Layer struct {
	layers.BaseLayer
	NextHeader   uint8    // Next header type after SRH
	HdrExtLen    uint8    // Length of SRH in 8-octet units, not including first 8 octets
	RoutingType  uint8    // Routing Type = 4 for SRv6
	SegmentsLeft uint8    // Number of route segments remaining
	LastEntry    uint8    // Index of the last element of the segment list
	Flags        uint8    // SRv6 flags
	Tag          uint16   // Tag field
	Segments     []net.IP // Segment list (each 16 bytes)
}

// LayerType returns the layer type for SRv6
func (s *SRv6Layer) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// SerializeTo serializes the SRv6 layer to bytes
func (s *SRv6Layer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// SRH length = 8 bytes (fixed header) + 16 bytes per segment
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

	// Write segments (in reverse order as per SRv6 spec - last segment first in wire format)
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

// BuildSRv6Packet creates an SRv6 packet with UDP payload
// Structure: Ethernet(14) + IPv6(40) + SRH(8+16*n) + UDP(8) + Payload
func BuildSRv6Packet(srcMAC, dstMAC [6]byte, srcIP, dstIP string, segments []string, srcPort, dstPort uint16, payload []byte) (*PacketInfo, error) {
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

	// Calculate SRH length: 8 bytes header + 16 bytes per segment
	srhLen := 8 + len(segments)*16
	// HdrExtLen is (length in 8-octet units) - 1, but actually it's (total length / 8) - 1
	// For SRH: (8 + n*16) / 8 - 1 = 1 + 2n - 1 = 2n for n segments
	hdrExtLen := uint8((srhLen / 8) - 1)

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
		NextHeader: layers.IPProtocolIPv6Routing, // 43
	}

	srh := &SRv6Layer{
		NextHeader:   uint8(layers.IPProtocolUDP), // 17
		HdrExtLen:    hdrExtLen,
		RoutingType:  4, // SRv6
		SegmentsLeft: uint8(len(segments) - 1),
		LastEntry:    uint8(len(segments) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentIPs,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip6, srh, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize SRv6 packet: %w", err)
	}

	// Calculate offsets
	// Ethernet: 0-13 (14 bytes)
	// IPv6: 14-53 (40 bytes)
	// SRH: 54 to 54+srhLen-1
	// UDP: 54+srhLen to 54+srhLen+7
	// Payload: 54+srhLen+8+
	srhOffset := uint64(54)
	udpOffset := srhOffset + uint64(srhLen)
	payloadOffset := udpOffset + 8

	return &PacketInfo{
		Data: buf.Bytes(),
		Offsets: map[string]uint64{
			"eth.dst":          0,
			"eth.src":          6,
			"ip6.hoplimit":     21,
			"ip6.src":          22,
			"ip6.dst":          38,
			"srh.segments_left": srhOffset + 3,
			"srh.segment0":     srhOffset + 8, // First segment in wire format (actually last in list)
			"udp.src":          udpOffset,
			"udp.dst":          udpOffset + 2,
			"payload":          payloadOffset,
		},
	}, nil
}
