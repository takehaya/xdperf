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
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)
	if err != nil {
		guest.Log(3, "failed to build sample packet: "+err.Error())
		return -5
	}
	maxLen := uint16(len(packetBytes))

	// Checksum specifications for IPv4/UDP packets
	// Type is auto-detected from packet content at IPHeaderOffset
	// srcPortOffset is the UDP header offset (Ethernet 14 + IP 20 = 34)
	ipHeaderOffset := uint16(srcPortOffset) - 20 // IP header starts 20 bytes before UDP
	checksums := []guest.ChecksumSpec{
		{
			// IPv4 header checksum (detected by csum_offset == ip_header_offset + 10)
			ChecksumOffset: ipHeaderOffset + 10,
			HeaderStart:    ipHeaderOffset,
			HeaderLen:      20, // IPv4 header length
			IPHeaderOffset: ipHeaderOffset,
		},
		{
			// UDP checksum (detected from IP protocol field)
			ChecksumOffset: uint16(srcPortOffset) + 6, // UDP checksum is at offset 6 from UDP header
			HeaderStart:    uint16(srcPortOffset),     // Start of UDP header
			HeaderLen:      0,                         // Computed from IP total length
			IPHeaderOffset: ipHeaderOffset,
		},
	}

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
