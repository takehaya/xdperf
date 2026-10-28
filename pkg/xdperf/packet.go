package xdperf

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (x *Xdperf) BuildSamplePacket() ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	payloadLen := 1500
	if x.mixed == nil && x.initialPacketLen != 0 {
		payloadLen = int(x.initialPacketLen)
	}
	var ethLayer gopacket.SerializableLayer
	var ipLayer gopacket.SerializableLayer
	var udpLayer *layers.UDP
	ethLayer = &layers.Ethernet{
		SrcMAC:       x.Device.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("127.0.0.1"),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer = &layers.UDP{
		SrcPort: layers.UDPPort(8080),
		DstPort: layers.UDPPort(8081),
	}
	err := udpLayer.SetNetworkLayerForChecksum(ip4)
	if err != nil {
		return nil, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}
	ipLayer = ip4
	payloadLen = payloadLen - 14 - 20 - 8
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = 'x'
	}
	err = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethLayer, ipLayer, udpLayer, gopacket.Payload(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}
	return buf.Bytes(), nil
}

// uniformPacketLen uses the effective lengths consumed by xdp_tx, including
// Raw entries and entries whose zero length falls back to their base.
func uniformPacketLen(bases []BasePacketInfo, entries []DiffEntry) uint16 {
	var length uint16
	for _, entry := range entries {
		if int(entry.BaseIdx) >= len(bases) {
			return 0
		}
		n := entry.PacketLen
		if n == 0 {
			n = bases[entry.BaseIdx].Base.Length
		}
		if n < 64 || n >= 1500 || (length != 0 && n != length) {
			return 0
		}
		length = n
	}
	return length
}
