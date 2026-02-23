package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildSRv6Variant(cfg VariantConfig) VariantResult {
	segments := []string{"2001:db8:1::1", "2001:db8:2::1"}
	pkt, err := BuildSRv6Packet(cfg.SrcMAC, cfg.DstMAC, cfg.SrcIPv6, cfg.DstIPv6, segments, cfg.SrcPort, cfg.DstPort, cfg.Payload)
	if err != nil {
		return VariantResult{Err: err}
	}

	// SRv6 header offsets: Ethernet(14) + IPv6(40) + SRH(8+2*16=40) = 94, UDP at 94
	// Minimum packet: 102 bytes (headers only), use 110 to have some payload
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["srh.segments_left"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 1}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 110, End: 1514}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: []guest.ChecksumSpec{
				{ChecksumOffset: 100, HeaderStart: 94, HeaderLen: 0, IPHeaderOffset: 14},
			},
			Weight: 1,
		},
	}
}

// SRv6Layer represents a Segment Routing Header (SRH) for IPv6
// Reference: https://github.com/nttcom/fluvia/blob/main/internal/pkg/meter/srv6.go
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
			"eth.dst":           0,
			"eth.src":           6,
			"ip6.hoplimit":      21,
			"ip6.src":           22,
			"ip6.dst":           38,
			"srh.segments_left": srhOffset + 3,
			"srh.segment0":      srhOffset + 8, // First segment in wire format (actually last in list)
			"udp.src":           udpOffset,
			"udp.dst":           udpOffset + 2,
			"payload":           payloadOffset,
		},
	}, nil
}
