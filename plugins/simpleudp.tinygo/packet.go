package main

import (
	"encoding/binary"
	"net"
)

type PacketBuilder struct {
	data []byte
}

func NewPacketBuilder(size int) *PacketBuilder {
	return &PacketBuilder{
		data: make([]byte, size),
	}
}

func (pb *PacketBuilder) Bytes() []byte {
	return pb.data
}

type EthernetHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

func (pb *PacketBuilder) WriteEthernet(offset int, eth *EthernetHeader) {
	copy(pb.data[offset:offset+6], eth.DstMAC[:])
	copy(pb.data[offset+6:offset+12], eth.SrcMAC[:])
	binary.BigEndian.PutUint16(pb.data[offset+12:offset+14], eth.EtherType)
}

type IPv4Header struct {
	Version        uint8 // 4 bits
	IHL            uint8 // 4 bits (Header Length in 32-bit words)
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint8  // 3 bits
	FragmentOffset uint16 // 13 bits
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

func (pb *PacketBuilder) WriteIPv4(offset int, ip *IPv4Header) {
	// Version(4) + IHL(4) = 1 byte
	pb.data[offset] = (ip.Version << 4) | ip.IHL
	pb.data[offset+1] = ip.TOS
	binary.BigEndian.PutUint16(pb.data[offset+2:offset+4], ip.TotalLength)
	binary.BigEndian.PutUint16(pb.data[offset+4:offset+6], ip.ID)

	// Flags(3) + Fragment Offset(13) = 2 bytes
	flagsAndOffset := (uint16(ip.Flags) << 13) | (ip.FragmentOffset & 0x1FFF)
	binary.BigEndian.PutUint16(pb.data[offset+6:offset+8], flagsAndOffset)

	pb.data[offset+8] = ip.TTL
	pb.data[offset+9] = ip.Protocol
	binary.BigEndian.PutUint16(pb.data[offset+10:offset+12], ip.Checksum)
	copy(pb.data[offset+12:offset+16], ip.SrcIP.To4())
	copy(pb.data[offset+16:offset+20], ip.DstIP.To4())
}

func (pb *PacketBuilder) CalculateIPv4Checksum(offset int, headerLen int) uint16 {
	// チェックサムフィールドを0にする
	pb.data[offset+10] = 0
	pb.data[offset+11] = 0

	sum := uint32(0)
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pb.data[offset+i : offset+i+2]))
	}

	// キャリーを加算
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func (pb *PacketBuilder) WriteUDP(offset int, udp *UDPHeader) {
	binary.BigEndian.PutUint16(pb.data[offset:offset+2], udp.SrcPort)
	binary.BigEndian.PutUint16(pb.data[offset+2:offset+4], udp.DstPort)
	binary.BigEndian.PutUint16(pb.data[offset+4:offset+6], udp.Length)
	binary.BigEndian.PutUint16(pb.data[offset+6:offset+8], udp.Checksum)
}

func (pb *PacketBuilder) CalculateUDPChecksum(ipOffset, udpOffset int, udpLen int) uint16 {
	pb.data[udpOffset+6] = 0
	pb.data[udpOffset+7] = 0

	sum := uint32(0)

	// 疑似ヘッダー: Source IP
	sum += uint32(binary.BigEndian.Uint16(pb.data[ipOffset+12 : ipOffset+14]))
	sum += uint32(binary.BigEndian.Uint16(pb.data[ipOffset+14 : ipOffset+16]))

	// 疑似ヘッダー: Destination IP
	sum += uint32(binary.BigEndian.Uint16(pb.data[ipOffset+16 : ipOffset+18]))
	sum += uint32(binary.BigEndian.Uint16(pb.data[ipOffset+18 : ipOffset+20]))

	// 疑似ヘッダー: Protocol + UDP Length
	sum += uint32(17) // UDP protocol number
	sum += uint32(udpLen)

	// UDPヘッダー + データ
	for i := 0; i < udpLen; i += 2 {
		if i+1 < udpLen {
			sum += uint32(binary.BigEndian.Uint16(pb.data[udpOffset+i : udpOffset+i+2]))
		} else {
			sum += uint32(pb.data[udpOffset+i]) << 8
		}
	}

	// キャリーを加算
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xFFFF // UDPの場合、0は0xFFFFに変換
	}

	return checksum
}

func (pb *PacketBuilder) WritePayload(offset int, payload []byte) {
	copy(pb.data[offset:], payload)
}

// BuildSimpleUDPPacket builds an Ethernet/IPv4/UDP frame. When vlanID != 0 an
// outer 802.1Q tag (priority vlanPCP) is inserted between the Ethernet header
// and IPv4; vlanID == 0 omits the tag entirely. Returns the packet bytes and the
// byte offset of the UDP source port (which shifts by 4 when tagged).
func BuildSimpleUDPPacket(srcMAC, dstMAC [6]byte, vlanID uint16, vlanPCP uint8, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, int) {
	vlanLen := 0
	if vlanID != 0 {
		vlanLen = 4
	}
	// Layer offsets, all shifted by the optional 4-byte VLAN tag.
	ipOffset := 14 + vlanLen
	udpOffset := ipOffset + 20
	payloadOffset := udpOffset + 8
	packetSize := payloadOffset + len(payload)
	pb := NewPacketBuilder(packetSize)

	// Ethernetヘッダー (tagged フレームでは EtherType が TPID 0x8100 になる)
	etherType := uint16(0x0800) // IPv4
	if vlanLen > 0 {
		etherType = 0x8100 // 802.1Q TPID
	}
	pb.WriteEthernet(0, &EthernetHeader{
		DstMAC:    dstMAC,
		SrcMAC:    srcMAC,
		EtherType: etherType,
	})
	if vlanLen > 0 {
		// 802.1Q tag: TCI (PCP(3)|DEI(1)|VID(12)) at offset 14, inner EtherType at 16.
		tci := (uint16(vlanPCP&0x7) << 13) | (vlanID & 0x0FFF)
		binary.BigEndian.PutUint16(pb.data[14:16], tci)
		binary.BigEndian.PutUint16(pb.data[16:18], 0x0800) // IPv4
	}

	// IPv4ヘッダー
	ipTotalLen := uint16(20 + 8 + len(payload))
	pb.WriteIPv4(ipOffset, &IPv4Header{
		Version:        4,
		IHL:            5, // 20 bytes / 4 = 5
		TOS:            0,
		TotalLength:    ipTotalLen,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       17, // UDP
		Checksum:       0,  // 後で計算
		SrcIP:          net.ParseIP(srcIP),
		DstIP:          net.ParseIP(dstIP),
	})

	// IPv4チェックサムの計算と設定
	ipChecksum := pb.CalculateIPv4Checksum(ipOffset, 20)
	binary.BigEndian.PutUint16(pb.data[ipOffset+10:ipOffset+12], ipChecksum)

	// UDPヘッダー
	udpLen := uint16(8 + len(payload))
	pb.WriteUDP(udpOffset, &UDPHeader{
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   udpLen,
		Checksum: 0, // 後で計算
	})

	// ペイロード
	if len(payload) > 0 {
		pb.WritePayload(payloadOffset, payload)
	}

	// UDPチェックサムの計算と設定
	udpChecksum := pb.CalculateUDPChecksum(ipOffset, udpOffset, int(udpLen))
	binary.BigEndian.PutUint16(pb.data[udpOffset+6:udpOffset+8], udpChecksum)

	return pb.Bytes(), udpOffset
}
