package main

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
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
	// show input
	guest.Log(1, "plugin_process called: count="+string(rune(req.Count)))
	guest.Log(1, "show input: "+string(reqJSON))

	// dummy ethernet packet as base_packet
	dstMAC := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// ペイロードの生成（最大サイズで作成、長さは LengthRange で変える）
	maxPayloadSize := req.PayloadSize + 100 // extra space for length variation
	payload := make([]byte, maxPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// UDPパケットの構築
	packetBytes := BuildSimpleUDPPacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)

	// create response with variable template
	// Packet structure:
	//   Ethernet header: 14 bytes (offset 0-13)
	//   IP header: 20 bytes (offset 14-33)
	//     - Source IP: offset 26-29 (last octet at 29)
	//   UDP header: 8 bytes (offset 34-41)
	//     - Source port: offset 34-35
	//     - Dst port: offset 36-37
	//   Payload: offset 42+
	//
	// Base packet length: Ethernet(14) + IP(20) + UDP(8) + Payload
	baseLen := uint16(14 + 20 + 8 + req.PayloadSize)
	maxLen := uint16(len(packetBytes))

	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: []guest.PacketVariant{
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen, // max length for base packet
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   34, // UDP src port offset
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 1024, End: 2048},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							ByteStart:   36, // UDP dst port offset
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 5000, End: 6024},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							// Special: vary packet length
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0, // ignored for packet length
							ByteRange:   guest.TemplateRange{Start: baseLen, End: baseLen + 50},
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Weight: 1,
				},
			},
			Pattern: guest.VariantSelectionModeSequential,
		},
	}

	// marshal to JSON
	wres, err := guest.WriteResponse(&res, outputPtr, outputMaxLen)
	if err != nil {
		guest.Log(3, "failed to write response: "+err.Error())
		return -3
	}

	guest.ReportMetric("gen resp count", float64(len(res.RawPacketTemplate)), time.Now().UnixNano())
	guest.Log(1, "response sent")
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
