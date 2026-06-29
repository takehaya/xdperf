package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ethHeaderLen = 14
	vlanTagLen   = 4 // one 802.1Q tag (TPID + TCI)
)

// BuildSamplePacket builds an Ethernet/IPv4/UDP frame. When vlanID != 0 an outer
// 802.1Q tag (with priority vlanPCP) is inserted between the Ethernet header and
// IPv4; vlanID == 0 omits the tag entirely. Returns the packet bytes and the
// byte offset of the UDP source port (which shifts by 4 when tagged).
func BuildSamplePacket(srcMAC, dstMAC [6]byte, vlanID uint16, vlanPCP uint8, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, uint64, error) {
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
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, 0, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	// Insert an optional 802.1Q tag; omit the layer entirely when untagged.
	vlanLen := 0
	serializableLayers := []gopacket.SerializableLayer{eth}
	if vlanID != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		serializableLayers = append(serializableLayers, &layers.Dot1Q{
			Priority:       vlanPCP,
			VLANIdentifier: vlanID,
			Type:           layers.EthernetTypeIPv4,
		})
		vlanLen = vlanTagLen
	}
	serializableLayers = append(serializableLayers, ip4, udpLayer, gopacket.Payload(payload))

	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		serializableLayers...,
	); err != nil {
		return nil, 0, fmt.Errorf("failed to serialize packet: %w", err)
	}

	srcPortOffset := ethHeaderLen + vlanLen + int(ip4.IHL)*4

	return buf.Bytes(), uint64(srcPortOffset), nil
}
