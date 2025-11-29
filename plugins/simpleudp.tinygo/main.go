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
	dmac, err := guest.NeighborResolve(req.DstIP, req.DeviceName)
	if err != nil {
		guest.Log(3, "failed to lookup neighbor: "+err.Error())
		return -4
	}
	if dmac != nil {
		copy(dstMAC[:], dmac)
		guest.Log(1, "resolved MAC address: "+string(dmac))
	}

	// ペイロードの生成（指定サイズ）
	payload := make([]byte, req.PayloadSize)
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

	// create response
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeRaw,
		RawPacketTemplate: []guest.BasePacket{
			{
				Data:   packetBytes,
				Length: uint16(len(packetBytes)),
			},
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
