package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildLLDPVariant(cfg VariantConfig) VariantResult {
	// LLDP destination is always the standard multicast address (IEEE 802.1AB)
	lldpDstMAC := [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}
	pkt, err := BuildLLDPPacket(cfg.SrcMAC, lldpDstMAC, "chassis1", "port1", 120)
	if err != nil {
		return VariantResult{Err: err}
	}

	// LLDP has no checksum, vary source MAC (last 2 bytes)
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["eth.src"] + 4, ByteSize: 2, ByteRange: guest.TemplateRange{Start: 0, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // LLDP has no checksum
			Weight:    1,
		},
	}
}

func BuildLLDPPacket(srcMAC, dstMAC [6]byte, chassisID string, portID string, ttl uint16) (*PacketInfo, error) {
	buf := gopacket.NewSerializeBuffer()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC[:]),
		DstMAC:       net.HardwareAddr(dstMAC[:]),
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
			"eth.dst":  0,
			"eth.src":  6,
			"lldp.tlv": 14, // Start of LLDP TLVs
			"lldp.ttl": 14 + 2 + 1 + 6 + 2 + 1 + uint64(len(portID)) + 2, // After chassis ID TLV and port ID TLV
		},
	}, nil
}
