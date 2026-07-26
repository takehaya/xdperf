package main

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
	"github.com/takehaya/xdperf/plugins/srv6/builder"
)

// dummy main to satisfy the Go compiler
func main() {}

//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	msg := goshim.PluginGeneratorInitRequest()
	guest.Log(1, "srv6 plugin initialized!: msg ->"+string(msg.PluginConfig))
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
	mode, err := builder.ParseMode(strings.ToLower(req.Mode))
	if err != nil {
		guest.Log(3, err.Error())
		return -6
	}
	// The segment list must fit the 8-bit Hdr Ext Len and contain only IPv6
	// addresses. Checked here (not just in the builder) so a bad config fails
	// with the config-error code before any packet is built.
	if len(req.Segments) == 0 {
		guest.Log(3, "segments must contain at least one IPv6 address")
		return -6
	}
	if len(req.Segments) > builder.MaxSegments {
		guest.Log(3, "segments must not exceed 127 entries")
		return -6
	}
	segments := make([]net.IP, len(req.Segments))
	for i, s := range req.Segments {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil {
			guest.Log(3, "segment is not an IPv6 address: "+s)
			return -6
		}
		segments[i] = ip.To16()
	}
	// The flow label is a 20-bit field; reject out-of-range values instead of
	// silently masking them.
	if req.FlowLabelStart > builder.FlowLabelMax || req.FlowLabelEnd > builder.FlowLabelMax {
		guest.Log(3, "flow_label_start/flow_label_end must be in 0-1048575")
		return -6
	}
	// _end below _start is a misconfiguration (equal = fixed field, end > start
	// = sweep); reject it rather than silently treating it as a fixed field.
	if req.FlowLabelEnd < req.FlowLabelStart {
		guest.Log(3, "flow_label_end must be >= flow_label_start")
		return -6
	}
	if req.SRHTagEnd < req.SRHTagStart {
		guest.Log(3, "srh_tag_end must be >= srh_tag_start")
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

	innerSrcMAC, ok := parseMAC(req.InnerSrcMac, "inner source")
	if !ok {
		return -5
	}
	innerDstMAC, ok := parseMAC(req.InnerDstMac, "inner destination")
	if !ok {
		return -5
	}

	// The outer destination defaults to the first segment to visit —
	// segments[0], since segments are given in visiting order. (On the wire the
	// SRH stores the list reversed, so this is the slot Segments Left points at.)
	dstIP := req.DstIP
	if dstIP == "" {
		dstIP = req.Segments[0]
	}

	// Resolve the outer destination MAC (static or via NDP).
	dstMAC, ok := parseMAC(req.DstMac, "destination")
	if !ok {
		return -5
	}
	if req.IsArpResolve {
		dmacstr, err := guest.NeighborResolve(dstIP, req.DeviceName)
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

	innerSrcIP, innerDstIP := req.InnerSrcIP, req.InnerDstIP
	if mode == builder.ModeIPv6 {
		innerSrcIP, innerDstIP = req.InnerSrcIP6, req.InnerDstIP6
	}
	params := builder.PacketParams{
		SrcMAC:       [6]byte(req.DeviceMacAddr),
		DstMAC:       dstMAC,
		SrcIP:        req.SrcIP,
		DstIP:        dstIP,
		TrafficClass: req.TrafficClass,
		FlowLabel:    req.FlowLabelStart,
		Mode:         mode,
		Segments:     segments,
		SRHTag:       req.SRHTagStart,
		InnerSrcMAC:  innerSrcMAC,
		InnerDstMAC:  innerDstMAC,
		InnerSrcIP:   innerSrcIP,
		InnerDstIP:   innerDstIP,
		InnerSrcPort: req.InnerSrcPort,
		InnerDstPort: req.InnerDstPort,
	}

	// Inner source IP sweep start, computed once (size-independent): the full
	// address as a big-endian uint32 in the IPv4 modes, the last hextet in ipv6
	// mode.
	var innerSrcIPVal, innerSrcIPEnd uint64
	if mode == builder.ModeIPv6 {
		innerSrcIPVal = ipv6LastHextet(innerSrcIP)
		innerSrcIPEnd = 0xFFFF
	} else {
		innerSrcIPVal = ipv4ToUint32(innerSrcIP)
		innerSrcIPEnd = 0xFFFFFFFF
	}

	// Diff/checksum budget per variant: flow label + SRH tag + inner src port +
	// inner dst port + inner src IP = 5 params (MAX_DIFFS_PER_PACKET is 8) and
	// at most 2 checksum specs (MAX_CHECKSUM_ENTRIES is 4).
	variants := make([]guest.PacketVariant, 0, len(req.IMIXSizes))
	minLen := builder.MinFrameLen(params)
	for i, size := range req.IMIXSizes {
		if size < minLen {
			guest.Log(2, "skipping imix size below minimum SRv6 frame length")
			continue
		}
		info, err := builder.BuildSRv6Packet(params, size)
		if err != nil {
			guest.Log(3, "failed to build SRv6 packet: "+err.Error())
			return -5
		}

		var vparams []guest.VariableParams
		// Flow label sequential variation. The flow label is the low 20 bits of
		// the first IPv6 word (version(4) | traffic class(8) | flow label(20)), and
		// the data plane only supports 1/2/4/6/8-byte diffs, so we write the whole
		// 4-byte word and bake the constant version/traffic-class prefix into both
		// ends of the range. flow_label_end <= 0xFFFFF keeps the prefix bits
		// untouched across the sweep, and the base packet is built with
		// flow_label_start so it matches the range start.
		if req.FlowLabelEnd > req.FlowLabelStart {
			prefix := uint64(6)<<28 | uint64(req.TrafficClass)<<20
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["outer.ip6.start"],
				ByteSize:    4,
				ByteRange:   guest.TemplateRange{Start: prefix | uint64(req.FlowLabelStart), End: prefix | uint64(req.FlowLabelEnd)},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// SRH tag sequential variation (16-bit field, direct 2-byte diff).
		if req.SRHTagEnd > req.SRHTagStart {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["srh.tag"],
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.SRHTagStart), End: uint64(req.SRHTagEnd)},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Inner UDP port sweeps (2 bytes each). Start at the configured port so
		// the base packet and the range stay in sync.
		if req.VaryInnerSrcPort {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["inner.udp.src"],
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.InnerSrcPort), End: 65535},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		if req.VaryInnerDstPort {
			vparams = append(vparams, guest.VariableParams{
				ByteStart:   info.Offsets["inner.udp.dst"],
				ByteSize:    2,
				ByteRange:   guest.TemplateRange{Start: uint64(req.InnerDstPort), End: 65535},
				PatternType: guest.ValuePatternTypeSequential,
			})
		}
		// Inner source IP sweep: full address (4 bytes) in the IPv4 modes, last
		// hextet (2 bytes) in ipv6 mode.
		if req.VaryInnerIP {
			if mode == builder.ModeIPv6 {
				vparams = append(vparams, guest.VariableParams{
					ByteStart:   info.Offsets["inner.ip6.src"] + 14,
					ByteSize:    2,
					ByteRange:   guest.TemplateRange{Start: innerSrcIPVal, End: innerSrcIPEnd},
					PatternType: guest.ValuePatternTypeSequential,
				})
			} else {
				vparams = append(vparams, guest.VariableParams{
					ByteStart:   info.Offsets["inner.ip.src"],
					ByteSize:    4,
					ByteRange:   guest.TemplateRange{Start: innerSrcIPVal, End: innerSrcIPEnd},
					PatternType: guest.ValuePatternTypeSequential,
				})
			}
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
		guest.Log(3, "no valid imix sizes (all below the minimum SRv6 frame length)")
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
	guest.Log(1, "srv6 plugin cleanup!: msg ->"+string(msg.PluginConfig))

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

// ipv6LastHextet returns the last 16-bit group of an IPv6 address as the sweep
// start value. An unparseable address yields 0, which is a harmless start.
func ipv6LastHextet(s string) uint64 {
	v6 := net.ParseIP(s).To16()
	if v6 == nil {
		return 0
	}
	return uint64(v6[14])<<8 | uint64(v6[15])
}
