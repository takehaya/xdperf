package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const ethHeaderLen = 14

func BuildSamplePacket(srcMAC, dstMAC [6]byte, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, uint64, error) {
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
	if err := udpLayer.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, 0, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}
	ipLayer = ip4

	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethLayer, ipLayer, udpLayer, gopacket.Payload(payload),
	); err != nil {
		return nil, 0, fmt.Errorf("failed to serialize packet: %w", err)
	}

	udpHeaderOffset := ethHeaderLen + int(ip4.IHL)*4
	srcPortOffset := udpHeaderOffset

	return buf.Bytes(), uint64(srcPortOffset), nil
}
