package main

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
)

// Packet offsets for IPv4/UDP
// Ethernet header: 0-13 (14 bytes)
//   - Dst MAC: 0-5 (6 bytes)
//   - Src MAC: 6-11 (6 bytes)
//   - EtherType: 12-13 (2 bytes)
// IPv4 header: 14-33 (20 bytes)
//   - Version/IHL: 14 (1 byte)
//   - TOS: 15 (1 byte)
//   - Total Length: 16-17 (2 bytes)
//   - ID: 18-19 (2 bytes)
//   - Flags/FragOffset: 20-21 (2 bytes)
//   - TTL: 22 (1 byte)
//   - Protocol: 23 (1 byte)
//   - Checksum: 24-25 (2 bytes)
//   - Src IP: 26-29 (4 bytes)
//   - Dst IP: 30-33 (4 bytes)
// UDP header: 34-41 (8 bytes)
//   - Src Port: 34-35 (2 bytes)
//   - Dst Port: 36-37 (2 bytes)
//   - Length: 38-39 (2 bytes)
//   - Checksum: 40-41 (2 bytes)
// Payload: 42+
const (
	OffsetDstMAC   = 0
	OffsetSrcMAC   = 6
	OffsetTOS      = 15
	OffsetIPID     = 18
	OffsetTTL      = 22
	OffsetSrcIP    = 26
	OffsetDstIP    = 30
	OffsetSrcPort  = 34
	OffsetDstPort  = 36
	OffsetPayload  = 42
	OffsetIPHeader = 14
)

// dummy main to satisfy Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	req, err := guest.ReadRequest[guest.GeneratorInitRequest](inputPtr, inputLen)
	if err != nil {
		guest.Log(3, "failed to read request: "+err.Error())
		return -1
	}
	guest.Log(1, "plugin initialized!"+": msg ->"+string(req.PluginConfig))
	guest.Log(1, "plugin version: "+version+", commit: "+commit+", date: "+date)
	res, err := guest.WriteResponse(&guest.GeneratorInitResponse{
		Success: true,
	}, outputPtr, outputMaxLen)
	if err != nil {
		guest.Log(3, "failed to write response: "+err.Error())
		return -3
	}
	guest.Log(1, "response sent")
	return res
}

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	req, err := guest.ReadRequest[GeneratorRequest](inputPtr, inputLen)
	if err != nil {
		guest.Log(3, "failed to read request: "+err.Error())
		return -1
	}
	reqJSON, _ := json.Marshal(req)
	guest.Log(1, "plugin_process called: count="+string(rune(req.Count)))
	guest.Log(1, "show input: "+string(reqJSON))

	// Parse destination MAC
	dstMAC := [6]byte{}
	dmac, err := guest.ParseMAC(req.DstMac)
	if err != nil {
		guest.Log(3, "failed to parse destination MAC address: "+err.Error())
		return -5
	}
	copy(dstMAC[:], dmac)
	if req.IsArpResolve {
		dmacstr, err := guest.NeighborResolve(req.DstIP, req.DeviceName)
		if err != nil {
			guest.Log(3, "failed to lookup neighbor: "+err.Error())
			return -4
		}
		if dmacstr != "" {
			guest.Log(1, "resolved MAC address: "+dmacstr)
			dmac, err := guest.ParseMAC(dmacstr)
			if err != nil {
				guest.Log(3, "failed to parse MAC address: "+err.Error())
				return -5
			}
			copy(dstMAC[:], dmac)
		}
	}
	if req.PayloadSize <= 0 {
		guest.Log(3, "invalid payload_size: must be positive")
		return -1
	}

	// Build base packet with large payload (for max packet length tests)
	// Use 1500 - 42 (headers) = 1458 bytes payload
	maxPayloadSize := 1458
	payload := make([]byte, maxPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	packetBytes := BuildSimpleUDPPacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)
	maxLen := uint16(len(packetBytes))

	// Checksum specifications for IPv4/UDP packets
	checksums := []guest.ChecksumSpec{
		{
			// IPv4 header checksum
			ChecksumOffset: 24,
			HeaderStart:    14,
			HeaderLen:      20,
			IPHeaderOffset: 14,
		},
		{
			// UDP checksum
			ChecksumOffset: 40,
			HeaderStart:    34,
			HeaderLen:      0,
			IPHeaderOffset: 14,
		},
	}

	// Build comprehensive test variants
	variants := []guest.PacketVariant{
		// ============================================================
		// Variant 0: 1-byte field test (TTL)
		// Tests ByteSize=1 with sequential pattern
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetTTL,
					ByteSize:    1,
					ByteRange:   guest.TemplateRange{Start: 32, End: 128},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 64}, // Fixed min length
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 1: 2-byte field test (UDP Src Port) + variable length
		// Tests ByteSize=2 with packet length variation
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 1024, End: 1124},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 128},
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    2,
		},

		// ============================================================
		// Variant 2: 4-byte field test (Src IP)
		// Tests ByteSize=4 - IPv4 address range
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcIP,
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: 0xC0A80101, End: 0xC0A801FE}, // 192.168.1.1 - 192.168.1.254
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 100, End: 100}, // Fixed length
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    2,
		},

		// ============================================================
		// Variant 3: 6-byte field test (Dst MAC)
		// Tests ByteSize=6 - MAC address variation
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetDstMAC,
					ByteSize:    6,
					ByteRange:   guest.TemplateRange{Start: 0x001122334455, End: 0x0011223344FF},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 64},
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 4: 8-byte field test (payload area)
		// Tests ByteSize=8 - largest supported field size
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetPayload,
					ByteSize:    8,
					ByteRange:   guest.TemplateRange{Start: 0x0000000000000001, End: 0x00000000000000FF},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 64},
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 5: Max diffs test (8 fields at once)
		// Tests MAX_DIFFS_PER_PACKET limit
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetTTL, // 1 byte
					ByteSize:    1,
					ByteRange:   guest.TemplateRange{Start: 64, End: 128},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetTOS, // 1 byte
					ByteSize:    1,
					ByteRange:   guest.TemplateRange{Start: 0, End: 63},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetIPID, // 2 bytes
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 1000, End: 2000},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetSrcPort, // 2 bytes
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 10000, End: 10100},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetDstPort, // 2 bytes
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 20000, End: 20100},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetSrcIP, // 4 bytes
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: 0x0A000001, End: 0x0A0000FF}, // 10.0.0.1 - 10.0.0.255
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetDstIP, // 4 bytes
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: 0x0A010001, End: 0x0A0100FF}, // 10.1.0.1 - 10.1.0.255
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 84},
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    3,
		},

		// ============================================================
		// Variant 6: Mixed pattern test (random values)
		// Tests ValuePatternTypeMixed for random generation
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 1024, End: 65535},
					PatternType: guest.ValuePatternTypeMixed, // Random!
				},
				{
					ByteStart:   OffsetDstPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 1, End: 1024},
					PatternType: guest.ValuePatternTypeMixed, // Random!
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 512},
					PatternType: guest.ValuePatternTypeMixed, // Random length!
				},
			},
			Checksums: checksums,
			Weight:    2,
		},

		// ============================================================
		// Variant 7: Fixed packet length (Start == End)
		// Tests edge case where length range is a single value
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 3000, End: 3100},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 256, End: 256}, // Fixed 256 bytes
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 8: Minimum packet length (64 bytes)
		// Tests minimum Ethernet frame size
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 4000, End: 4100},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 64}, // Minimum
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 9: Maximum packet length (1500 bytes)
		// Tests MTU-sized packets
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 5000, End: 5100},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 1500, End: 1500}, // Maximum (MTU)
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 10: Single value range for field (Start == End)
		// Tests edge case where field value is fixed but length varies
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 12345, End: 12345}, // Fixed port
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetDstPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 80, End: 80}, // Fixed port
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 64, End: 1500}, // Full range
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    1,
		},

		// ============================================================
		// Variant 11: Multiple fields changing together
		// Tests Src IP + Dst IP + Src Port + Dst Port all varying
		// ============================================================
		{
			Base: guest.BasePacket{
				Data:   packetBytes,
				Length: maxLen,
			},
			Params: []guest.VariableParams{
				{
					ByteStart:   OffsetSrcIP,
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: 0xAC100001, End: 0xAC1000FF}, // 172.16.0.1 - 172.16.0.255
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetDstIP,
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: 0xAC110001, End: 0xAC1100FF}, // 172.17.0.1 - 172.17.0.255
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetSrcPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 32768, End: 32868},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   OffsetDstPort,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: 443, End: 543},
					PatternType: guest.ValuePatternTypeSequential,
				},
				{
					ByteStart:   guest.ByteStartPacketLength,
					ByteSize:    0,
					ByteRange:   guest.TemplateRange{Start: 128, End: 256},
					PatternType: guest.ValuePatternTypeSequential,
				},
			},
			Checksums: checksums,
			Weight:    2,
		},
	}

	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: variants,
			Pattern:  guest.VariantSelectionModeMixed, // Weighted random selection
		},
	}

	wres, err := guest.WriteResponse(&res, outputPtr, outputMaxLen)
	if err != nil {
		guest.Log(3, "failed to write response: "+err.Error())
		return -3
	}

	guest.ReportMetric("gen resp count", float64(len(variants)), time.Now().UnixNano())
	guest.Log(1, "response sent with "+string(rune('0'+len(variants)))+" variants")
	return wres
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	req, err := guest.ReadRequest[guest.GeneratorCleanupRequest](inputPtr, inputLen)
	if err != nil {
		guest.Log(3, "failed to read request: "+err.Error())
		return -1
	}
	guest.Log(1, "plugin cleanup called: msg ->"+string(req.PluginConfig))

	res, err := guest.WriteResponse(&guest.GeneratorCleanupResponse{
		Success: true,
	}, outputPtr, outputMaxLen)
	if err != nil {
		guest.Log(3, "failed to write response: "+err.Error())
		return -3
	}
	guest.Log(1, "cleanup response sent")
	return res
}
