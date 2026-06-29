package main

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
	"github.com/takehaya/xdperf/plugins/vxlan/builder"
)

// dummy main to satisfy the Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorInitRequest()
	guest.Log(1, "vxlan plugin initialized!: msg ->"+string(msg.PluginConfig))
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
	// VNI is a 24-bit field; reject out-of-range values instead of silently
	// masking them.
	if req.VNIStart > 0xFFFFFF || req.VNIEnd > 0xFFFFFF {
		guest.Log(3, "vni_start/vni_end must be in 0-16777215")
		return -6
	}
	// _end below _start is a misconfiguration (equal = fixed field, end > start
	// = sweep); reject it rather than silently treating it as a fixed field.
	if req.VNIEnd < req.VNIStart {
		guest.Log(3, "vni_end must be >= vni_start")
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
	// inner_mode is documented as ip|l2only; reject unknown non-empty values
	// instead of silently falling back to the default (empty means "ip").
	l2only := false
	switch strings.ToLower(req.InnerMode) {
	case "", "ip":
	case "l2only":
		l2only = true
	default:
		guest.Log(3, "inner_mode must be 'ip' or 'l2only'")
		return -6
	}

	// parseMAC parses a MAC string into a fixed array, logging and reporting
	// failure (so the caller can return the -5 parse-error code).
	parseMAC := func(s, label string) ([6]byte, bool) {
		var out [6]byte
		b, err := guest.ParseMAC(s)
		if err != nil {
			guest.Log(3, "failed to parse "+label+" MAC address: "+err.Error())
			return out, false
		}
		copy(out[:], b)
		return out, true
	}

	// Resolve the inner Ethernet MACs (static).
	innerSrcMAC, ok := parseMAC(req.InnerSrcMac, "inner source")
	if !ok {
		return -5
	}
	innerDstMAC, ok := parseMAC(req.InnerDstMac, "inner destination")
	if !ok {
		return -5
	}

	// Resolve the outer destination MAC (static or via ARP/NDP).
	dstMAC, ok := parseMAC(req.DstMac, "destination")
	if !ok {
		return -5
	}
	if req.IsArpResolve {
		dmacstr, err := guest.NeighborResolve(req.DstIP, req.DeviceName)
		if err != nil {
			guest.Log(3, "failed to lookup neighbor: "+err.Error())
			return -4
		}
		if dmacstr != "" {
			guest.Log(1, "resolved MAC address: "+dmacstr)
			rmac, rok := parseMAC(dmacstr, "resolved")
			if !rok {
				return -5
			}
			dstMAC = rmac
		}
	}

	params := builder.PacketParams{
		SrcMAC:           [6]byte(req.DeviceMacAddr),
		DstMAC:           dstMAC,
		SrcIP:            req.SrcIP,
		DstIP:            req.DstIP,
		OuterSrcPort:     req.SrcPort,
		OuterDstPort:     req.DstPort,
		VNI:              req.VNIStart,
		InnerSrcMAC:      innerSrcMAC,
		InnerDstMAC:      innerDstMAC,
		InnerSrcIP:       req.InnerSrcIP,
		InnerDstIP:       req.InnerDstIP,
		InnerSrcPort:     req.InnerSrcPort,
		InnerDstPort:     req.InnerDstPort,
		InnerUDPChecksum: req.InnerUDPChecksum,
		InnerL2Only:      l2only,
	}

	// Inner source IP as a big-endian uint32, used as the sweep start; computed
	// once since it does not depend on the IMIX size.
	innerSrcIPVal := ipv4ToUint32(req.InnerSrcIP)

	variants := make([]guest.PacketVariant, 0, len(req.IMIXSizes))
	minLen := builder.MinFrameLen(params)
	for i, size := range req.IMIXSizes {
		if size < minLen {
			guest.Log(2, "skipping imix size below minimum VXLAN frame length")
			continue
		}
		info, err := builder.BuildVXLANPacket(params, size)
		if err != nil {
			guest.Log(3, "failed to build VXLAN packet: "+err.Error())
			return -5
		}

		var vparams []guest.VariableParams
		// VNI sequential variation. The VNI is a 24-bit field, but the data plane
		// only supports 1/2/4/6/8-byte diffs, so we write 4 bytes starting one
		// octet earlier (the reserved byte before the VNI). A VNI of 0..0xFFFFFF
		// big-endian leaves that leading reserved byte 0, matching the base packet,
		// so the layout stays correct while the 24-bit VNI is updated.
		if req.VNIEnd > req.VNIStart {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["vxlan.start"] + 3,
				ByteSize:    4,
				ByteRange:   guest.TemplateRange{Start: uint64(req.VNIStart), End: uint64(req.VNIEnd)},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Inner UDP source port sweep (2 bytes). Starts at inner_src_port so the
		// base packet and the range stay in sync. Absent in l2only mode (no inner
		// L4), so it is gated on the offset existing.
		if off, ok := info.Offsets["inner.udp.src"]; ok && req.VaryInnerPort {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   off,
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.InnerSrcPort), End: 65535},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Inner source IP sweep (4 bytes). Absent in l2only mode (no inner L3).
		if off, ok := info.Offsets["inner.ip.src"]; ok && req.VaryInnerIP {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   off,
				ByteSize:    4,
				ByteRange:   guest.TemplateRange{Start: innerSrcIPVal, End: 0xFFFFFFFF},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Outer UDP source port sweep (2 bytes). Starts at src_port.
		if req.VaryOuterPort {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["outer.udp.src"],
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.SrcPort), End: 65535},
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
		guest.Log(3, "no valid imix sizes (all below the minimum VXLAN frame length)")
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
	guest.Log(1, "vxlan plugin cleanup!: msg ->"+string(msg.PluginConfig))

	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{
		Success: true,
	})
	return 0
}

// ipv4ToUint32 parses a dotted-quad IPv4 string into its big-endian uint32
// value. An unparseable address yields 0, which is a harmless sweep start.
func ipv4ToUint32(s string) uint64 {
	v4 := net.ParseIP(s).To4()
	if v4 == nil {
		return 0
	}
	return uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
}
