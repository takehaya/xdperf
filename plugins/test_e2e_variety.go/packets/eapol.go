package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildEAPoLVariant(cfg VariantConfig) VariantResult {
	// EAPoL-Start has empty body
	pkt, err := BuildEAPoLPacket(cfg.SrcMAC, cfg.DstMAC, layers.EAPOLTypeStart, nil)
	if err != nil {
		return VariantResult{Err: err}
	}

	// EAPoL has no checksum, vary source MAC
	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: pkt.Offsets["eth.src"] + 4, ByteSize: 2, ByteRange: guest.TemplateRange{Start: 0, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // EAPoL has no checksum
			Weight:    1,
		},
	}
}

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
