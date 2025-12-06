package main

import (
	"encoding/json"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
)

// dummy main to satisfy Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorInitRequest()
	guest.Log(1, "plugin initialized!: msg ->"+string(msg.PluginConfig))
	guest.Log(1, "plugin version: "+version+", commit: "+commit+", date: "+date)

	goshim.PluginGeneratorInitResponse(guest.GeneratorInitResponse{
		Success: true,
	})
	return 1
}

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	req := goshim.PluginGeneratorProcessRequest[GeneratorRequest]()

	// show input
	reqJSON, _ := json.Marshal(req)
	guest.Log(1, "plugin_process called with input: "+string(reqJSON))

	// dummy ethernet packet as base_packet
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

	// ペイロードの生成（指定サイズ）
	payload := make([]byte, req.PayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	packetBytes, err := BuildSamplePacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)
	if err != nil {
		guest.Log(3, "failed to build sample packet: "+err.Error())
		return -5
	}
	maxLen := uint16(len(packetBytes))

	// create response
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: []guest.PacketVariant{
				// Variant A: Short packets (64-84 bytes), SrcPort 1024-1124, Weight=3 (75%)
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   34, // UDP src port offset
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 1024, End: 1124},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0,
							ByteRange:   guest.TemplateRange{Start: 64, End: 84}, // Short: 64-84 bytes
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Weight: 3,
				},
				// Variant B: Long packets (200-220 bytes), SrcPort 2000-2100, Weight=1 (25%)
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   34, // UDP src port offset
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 2000, End: 2100},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0,
							ByteRange:   guest.TemplateRange{Start: 200, End: 220}, // Long: 200-220 bytes
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Weight: 1,
				},
				// Variant C: Varying source IP (4 bytes), Weight=1
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   26, // IPv4 src IP offset
							ByteSize:    4,
							ByteRange:   guest.TemplateRange{Start: 0xC0A80101, End: 0xC0A801FE}, // 192.168.1.1 - 192.168.1.254
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Weight: 1,
				},
			},
			// VariantSelectionModeMixed: weighted selection (A=75%, B=25%)
			Pattern: guest.VariantSelectionModeMixed,
		},
	}

	goshim.PluginGeneratorProcessResponse(res)

	guest.ReportMetric("gen resp count", 1, time.Now().UnixNano())
	guest.Log(1, "response sent")
	return int32(len(packetBytes))
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorCleanupRequest()
	guest.Log(1, "plugin cleanup")
	guest.Log(1, "plugin cleanup!: msg ->"+string(msg.PluginConfig))

	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{
		Success: true,
	})
	return 0
}
