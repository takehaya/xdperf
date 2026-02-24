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
	payload := make([]byte, req.PayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Packet structure:
	//   Ethernet header: 14 bytes (offset 0-13)
	//   IP header: 20 bytes (offset 14-33)
	//     - Dst IP: offset 30-33 (last octet at 33)
	//   UDP header: 8 bytes (offset 34-41)
	//     - Source port: offset 34-35
	//     - Dst port: offset 36-37
	//   Payload: offset 42+
	// Both variants use the same base packet
	packetBytes := BuildSimpleUDPPacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)
	maxLen := uint16(len(packetBytes))

	// Checksum specifications for IPv4/UDP packets
	// Type is auto-detected from packet content at IPHeaderOffset
	checksums := []guest.ChecksumSpec{
		{
			// IPv4 header checksum (detected by csum_offset == ip_header_offset + 10)
			ChecksumOffset: 24, // 14 (Ethernet) + 10 (IP header offset to checksum)
			HeaderStart:    14, // Start of IP header
			HeaderLen:      20, // IPv4 header length
			IPHeaderOffset: 14,
		},
		{
			// UDP checksum (detected from IP protocol field)
			ChecksumOffset: 40, // 34 (UDP start) + 6 (checksum offset in UDP)
			HeaderStart:    34, // Start of UDP header
			HeaderLen:      0,  // Computed from IP total length
			IPHeaderOffset: 14,
		},
	}

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
							ByteStart:   34, // UDP src port offset
							ByteSize:    2,
							ByteRange:   guest.TemplateRange{Start: 1024, End: 1124},
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
