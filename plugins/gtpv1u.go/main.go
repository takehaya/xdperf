package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
	"github.com/takehaya/xdperf/plugins/gtpv1u/builder"
)

// dummy main to satisfy the Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorInitRequest()
	guest.Log(1, "gtpv1u plugin initialized!: msg ->"+string(msg.PluginConfig))
	guest.Log(1, "plugin version: "+version+", commit: "+commit+", date: "+date)

	goshim.PluginGeneratorInitResponse(guest.GeneratorInitResponse{
		Success: true,
	})
	return 1
}

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	req := goshim.PluginGeneratorProcessRequest[GeneratorRequest]()

	reqJSON, _ := json.Marshal(req)
	guest.Log(1, "plugin_process called with input: "+string(reqJSON))

	if len(req.IMIXSizes) == 0 {
		guest.Log(3, "imix_sizes must not be empty")
		return -6
	}
	// QFI is a 6-bit field; reject out-of-range values instead of silently
	// masking them (which would turn e.g. 64 into 0).
	if req.QFIStart > 63 || req.QFIEnd > 63 {
		guest.Log(3, "qfi_start/qfi_end must be in 0-63")
		return -6
	}
	// _end below _start is a misconfiguration (equal = fixed field, end > start
	// = sweep); reject it rather than silently treating it as a fixed field.
	if req.TEIDEnd < req.TEIDStart {
		guest.Log(3, "teid_end must be >= teid_start")
		return -6
	}
	if req.EnablePSC && req.QFIEnd < req.QFIStart {
		guest.Log(3, "qfi_end must be >= qfi_start")
		return -6
	}
	// Negative weights would wrap to huge uint32 values and break variant
	// selection.
	for _, w := range req.IMIXWeights {
		if w < 0 {
			guest.Log(3, "imix_weights must not be negative")
			return -6
		}
	}
	// pdu_type / inner_proto are documented as dl|ul and udp|icmp; reject unknown
	// non-empty values instead of silently falling back to the default (empty
	// means "use the default": dl / udp).
	switch strings.ToLower(req.PDUType) {
	case "", "dl", "ul":
	default:
		guest.Log(3, "pdu_type must be 'dl' or 'ul'")
		return -6
	}
	switch strings.ToLower(req.InnerProto) {
	case "", "udp", "icmp":
	default:
		guest.Log(3, "inner_proto must be 'udp' or 'icmp'")
		return -6
	}

	// Resolve the destination MAC (static or via ARP/NDP).
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
			rmac, err := guest.ParseMAC(dmacstr)
			if err != nil {
				guest.Log(3, "failed to parse MAC address: "+err.Error())
				return -5
			}
			copy(dstMAC[:], rmac)
		}
	}

	params := builder.PacketParams{
		SrcMAC:           [6]byte(req.DeviceMacAddr),
		DstMAC:           dstMAC,
		SrcIP:            req.SrcIP,
		DstIP:            req.DstIP,
		OuterSrcPort:     req.SrcPort,
		TEID:             req.TEIDStart,
		EnablePSC:        req.EnablePSC,
		EnableSeq:        req.EnableSeq,
		PDUTypeUL:        strings.EqualFold(req.PDUType, "ul"),
		RQI:              req.RQI,
		QFI:              req.QFIStart,
		InnerProto:       req.InnerProto,
		InnerUDPChecksum: req.InnerUDPChecksum,
		InnerSrcIP:       req.InnerSrcIP,
		InnerDstIP:       req.InnerDstIP,
		InnerSrcPort:     req.InnerSrcPort,
		InnerDstPort:     req.InnerDstPort,
	}

	variants := make([]guest.PacketVariant, 0, len(req.IMIXSizes))
	minLen := builder.MinFrameLen(params)
	for i, size := range req.IMIXSizes {
		if size < minLen {
			guest.Log(2, "skipping imix size below minimum GTP-U frame length")
			continue
		}
		info, err := builder.BuildGTPv1UPacket(params, size)
		if err != nil {
			guest.Log(3, "failed to build GTP-U packet: "+err.Error())
			return -5
		}

		var vparams []guest.VariableParams
		// TEID sequential variation (gtp.teid, 4 bytes).
		if req.TEIDEnd > req.TEIDStart {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["gtp.teid"],
				ByteSize:    4,
				ByteRange:   guest.TemplateRange{Start: uint64(req.TEIDStart), End: uint64(req.TEIDEnd)},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// QFI sequential variation inside the PSC extension header (1 byte). The
		// byte range carries the RQI bit so it survives the diff. RQI is
		// downlink-only, so it is never set for an uplink container.
		if req.EnablePSC && req.QFIEnd > req.QFIStart {
			rqiBit := uint64(0)
			if req.RQI && !params.PDUTypeUL {
				rqiBit = 0x40
			}
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["psc.qfi"],
				ByteSize:    1,
				ByteRange:   guest.TemplateRange{Start: rqiBit | uint64(req.QFIStart), End: rqiBit | uint64(req.QFIEnd)},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Optional inner UDP source port variation (2 bytes). Only applies to an
		// inner UDP T-PDU; for inner ICMP there is no port offset. The sweep
		// starts at inner_src_port so the base packet and the range stay in sync.
		if off, ok := info.Offsets["inner.udp.src"]; ok && req.VaryInnerPort {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   off,
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.InnerSrcPort), End: 65535},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}

		weight := uint32(1)
		if i < len(req.IMIXWeights) {
			weight = uint32(req.IMIXWeights[i])
		}

		variants = append(variants, guest.PacketVariant{
			Base: guest.BasePacket{
				Data:   info.Data,
				Length: uint16(len(info.Data)),
			},
			Params:    vparams,
			Checksums: info.Checksums,
			Weight:    weight,
		})
	}

	if len(variants) == 0 {
		guest.Log(3, "no valid imix sizes (all below the minimum GTP-U frame length)")
		return -6
	}

	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: variants,
			// Weighted random selection across the fixed-size variants (IMIX).
			Pattern: guest.VariantSelectionModeMixed,
		},
	}

	goshim.PluginGeneratorProcessResponse(res)
	guest.ReportMetric("gen resp count", float64(len(variants)), time.Now().UnixNano())
	guest.Log(1, "response sent")
	return int32(len(variants))
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorCleanupRequest()
	guest.Log(1, "gtpv1u plugin cleanup!: msg ->"+string(msg.PluginConfig))

	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{
		Success: true,
	})
	return 0
}
