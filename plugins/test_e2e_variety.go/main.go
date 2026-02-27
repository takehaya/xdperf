package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
	"github.com/takehaya/xdperf/plugins/test_e2e_variety/packets"
)

// dummy main to satisfy Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorInitRequest()
	guest.Log(1, fmt.Sprintf("plugin initialized!: msg ->%s", string(msg.PluginConfig)))
	guest.Log(1, fmt.Sprintf("plugin version: %s, commit: %s, date: %s", version, commit, date))

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
	guest.Log(1, fmt.Sprintf("plugin_process called with input: %s", string(reqJSON)))

	// Parse destination MAC
	dstMAC := [6]byte{}
	dmac, err := guest.ParseMAC(req.DstMac)
	if err != nil {
		guest.Log(3, fmt.Sprintf("failed to parse destination MAC address: %v", err))
		return -5
	}
	copy(dstMAC[:], dmac)
	if req.IsArpResolve {
		dmacstr, err := guest.NeighborResolve(req.DstIP, req.DeviceName)
		if err != nil {
			guest.Log(3, fmt.Sprintf("failed to lookup neighbor: %v", err))
			return -4
		}
		if dmacstr != "" {
			guest.Log(1, fmt.Sprintf("resolved MAC address: %s", dmacstr))
			dmac, err := guest.ParseMAC(dmacstr)
			if err != nil {
				guest.Log(3, fmt.Sprintf("failed to parse MAC address: %v", err))
				return -5
			}
			copy(dstMAC[:], dmac)
		}
	}

	srcMAC := [6]byte(req.DeviceMacAddr)

	// Build large payload for max packet tests
	maxPayloadSize := 1458 // 1500 - 42 (headers)
	payload := make([]byte, maxPayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Create variant config
	cfg := packets.VariantConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   req.SrcIP,
		DstIP:   req.DstIP,
		SrcIPv6: req.SrcIPv6,
		DstIPv6: req.DstIPv6,
		SrcPort: req.SrcPort,
		DstPort: req.DstPort,
		Payload: payload,
	}

	// Build variants using registry
	variants := []guest.PacketVariant{}
	for _, proto := range req.GetProtocolsToInclude() {
		builder, ok := packets.Registry[proto]
		if !ok {
			guest.Log(2, fmt.Sprintf("unknown protocol: %s", proto))
			continue
		}

		result := builder(cfg)
		if result.Err != nil {
			guest.Log(2, fmt.Sprintf("failed to build %s packet: %v", proto, result.Err))
			continue
		}

		if len(result.Variants) > 0 {
			variants = append(variants, result.Variants...)
		} else if result.Variant != nil {
			variants = append(variants, *result.Variant)
		}
	}

	if len(variants) == 0 {
		guest.Log(3, "no variants built")
		return -1
	}

	// Create response
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: variants,
			Pattern:  guest.VariantSelectionModeMixed,
		},
	}

	goshim.PluginGeneratorProcessResponse(res)

	guest.ReportMetric("gen resp count", float64(len(variants)), time.Now().UnixNano())
	guest.Log(1, fmt.Sprintf("response sent with variants: %d", len(variants)))
	return int32(len(variants))
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorCleanupRequest()
	guest.Log(1, "plugin cleanup")
	guest.Log(1, fmt.Sprintf("plugin cleanup!: msg ->%s", string(msg.PluginConfig)))

	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{
		Success: true,
	})
	return 0
}
