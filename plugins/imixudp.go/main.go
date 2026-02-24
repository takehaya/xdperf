package main

import (
	"encoding/json"
	"net"
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

	if req.IMIXRatio == nil || len(req.IMIXRatio) != 3 {
		guest.Log(3, "invalid IMIX ratio, must be an array of 3 integers")
		return -6
	}

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

	packetBytes, v4srcIPOffset, srcPortOffset, err := BuildSamplePacket(
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
	// imix pattern with 3 variants
	// Variant A: Short packets (64-84 bytes), SrcPort 1024-1124, Weight=60%
	// Variant B: Mid packets (500-600 bytes), SrcPort 2000-2100, Weight=34%
	// Variant C: Large Packets with varying source IP (4 bytes, 1500 bytes), Weight=6%
	// Total Weight = 100%
	// can be overridden by req.IMIXRatio
	// hint: https://github.com/cisco-system-traffic-generator/trex-core/blob/master/scripts/stl/imix.py
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: []guest.PacketVariant{
				// Variant A: Short packets (64-84 bytes), SrcPort 1024-1124, Weight=60%
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
						{
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0,
							ByteRange:   guest.TemplateRange{Start: 64, End: 84}, // Short: 64-84 bytes
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Checksums: checksums,
					Weight:    uint32(req.IMIXRatio[0]),
				},
				// Variant B: Mid packets (500-600 bytes), SrcPort 2000-2100, Weight=34%
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart:   srcPortOffset,
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 2000, End: 2100},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0,
							ByteRange:   guest.TemplateRange{Start: 500, End: 600},
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Checksums: checksums,
					Weight:    uint32(req.IMIXRatio[1]),
				},
				// Variant C: Varying source IP (4 bytes, 1500 bytes), Weight=6%
				{
					Base: guest.BasePacket{
						Data:   packetBytes,
						Length: maxLen,
					},
					Params: []guest.VariableParams{
						{
							ByteStart: v4srcIPOffset,
							ByteSize:  4,
							ByteRange: guest.TemplateRange{ // 192.168.1.1 - 192.168.1.254
								Start: uint64(IPv4ToUint32(net.ParseIP("192.168.1.1"))),
								End:   uint64(IPv4ToUint32(net.ParseIP("192.168.1.254"))),
							},
							PatternType: guest.ValuePatternTypeSequential,
						},
						{
							ByteStart:   guest.ByteStartPacketLength,
							ByteSize:    0,
							ByteRange:   guest.TemplateRange{Start: 1500, End: 1500},
							PatternType: guest.ValuePatternTypeSequential,
						},
					},
					Checksums: checksums,
					Weight:    uint32(req.IMIXRatio[2]),
				},
			},
			// VariantSelectionModeMixed: weighted selection (A 60%, B 34%, C 6%)
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