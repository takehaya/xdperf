package main

import (
	"encoding/json"
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
			guest.Log(2, "unknown protocol: "+proto)
			continue
		}

		result := builder(cfg)
		if result.Err != nil {
			guest.Log(2, "failed to build "+proto+" packet: "+result.Err.Error())
			continue
		}

		variants = append(variants, *result.Variant)
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
	guest.Log(1, "response sent with variants: "+string(rune('0'+len(variants)/10))+string(rune('0'+len(variants)%10)))
	return int32(len(variants))
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
