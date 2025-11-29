package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func BuildSamplePacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	var ethLayer gopacket.SerializableLayer
	var ipLayer gopacket.SerializableLayer
	var udpLayer *layers.UDP
	ethLayer = &layers.Ethernet{
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
	udpLayer = &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	err := udpLayer.SetNetworkLayerForChecksum(ip4)
	if err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}
	ipLayer = ip4
	// Use the provided payload directly instead of recomputing or shadowing the variable.
	err = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethLayer, ipLayer, udpLayer, gopacket.Payload(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}
	return buf.Bytes(), nil
}
