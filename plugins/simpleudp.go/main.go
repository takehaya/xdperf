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

	// create response
	res := guest.GeneratorProcessResponse{
		TemplateType: "raw",
		RawPacketTemplate: []guest.BasePacket{
			{
				Data:   packetBytes,
				Length: uint16(len(packetBytes)),
			},
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
