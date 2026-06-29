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

	payload := make([]byte, req.PayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	packetBytes, srcPortOffset, err := BuildSamplePacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.VLANID, req.VLANPCP,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)
	if err != nil {
		guest.Log(3, "failed to build sample packet: "+err.Error())
		return -5
	}
	maxLen := uint16(len(packetBytes))

	// Checksum specs for an Ethernet/IPv4/UDP frame. The IPv4 header begins one
	// IPv4 header before the UDP header (srcPortOffset - IPv4HeaderLen).
	checksums := guest.IPv4UDPChecksumSpecs(uint16(srcPortOffset) - guest.IPv4HeaderLen)

	// create response
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: []guest.PacketVariant{
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   srcPortOffset,
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 1024, End: 1124},
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Checksums: checksums,
				},
			},
			Pattern: guest.VariantSelectionModeSequential,
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
