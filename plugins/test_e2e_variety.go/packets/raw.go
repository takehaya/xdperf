package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/guest"
)

func BuildRawVariant(cfg VariantConfig) VariantResult {
	rawPayload := make([]byte, 46)
	for i := range rawPayload {
		rawPayload[i] = byte(i)
	}
	pkt, err := BuildRawEthernetFrame(cfg.SrcMAC, cfg.DstMAC, 0x9000, rawPayload)
	if err != nil {
		return VariantResult{Err: err}
	}

	return VariantResult{
		Variant: &guest.PacketVariant{
			Base: guest.BasePacket{Data: pkt.Data, Length: uint16(len(pkt.Data))},
			Params: []guest.VariableParams{
				// EtherType is fixed at 0x9000 (custom protocol)
				// Only vary payload content
				{ByteStart: pkt.Offsets["payload"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0, End: 0xFFFFFFFF}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 64}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil,
			Weight:    1,
		},
	}
}

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
			"eth.dst":  0,
			"eth.src":  6,
			"eth.type": 12,
			"payload":  14,
		},
	}, nil
}
