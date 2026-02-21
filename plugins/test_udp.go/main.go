package main

import (
	"encoding/json"
	"time"

	"github.com/google/gopacket/layers"
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

	variants := []guest.PacketVariant{}

	// ============================================================
	// IPv4 UDP Variant (combined: TTL + TOS + Port + IP + MAC + Payload)
	// Tests: 1B, 2B, 4B, 6B, 8B fields, odd offsets (15, 43)
	// ============================================================
	ipv4Pkt, err := BuildIPv4UDPPacket(srcMAC, dstMAC, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(3, "failed to build IPv4 UDP packet: "+err.Error())
		return -1
	}
	ipv4Checksums := []guest.ChecksumSpec{
		{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14},
		{ChecksumOffset: 40, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},
	}

	variants = append(variants, guest.PacketVariant{
		Base:   guest.BasePacket{Data: ipv4Pkt.Data, Length: uint16(len(ipv4Pkt.Data))},
		Params: []guest.VariableParams{
			{ByteStart: ipv4Pkt.Offsets["ip.ttl"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 64, End: 128}, PatternType: guest.ValuePatternTypeSequential},
			{ByteStart: ipv4Pkt.Offsets["ip.tos"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 63}, PatternType: guest.ValuePatternTypeSequential},    // odd offset 15
			{ByteStart: ipv4Pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
			{ByteStart: ipv4Pkt.Offsets["ip.src"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0xC0A80101, End: 0xC0A801FE}, PatternType: guest.ValuePatternTypeSequential},
			{ByteStart: ipv4Pkt.Offsets["eth.dst"], ByteSize: 6, ByteRange: guest.TemplateRange{Start: 0x001122334455, End: 0x0011223344FF}, PatternType: guest.ValuePatternTypeSequential},
			{ByteStart: ipv4Pkt.Offsets["payload"] + 1, ByteSize: 8, ByteRange: guest.TemplateRange{Start: 1, End: 255}, PatternType: guest.ValuePatternTypeSequential}, // odd offset 43
			{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 256}, PatternType: guest.ValuePatternTypeSequential},
		},
		Checksums: ipv4Checksums,
		Weight:    1,
	})

	// ============================================================
	// IPv6 UDP Variant (combined: HopLimit + Port + IP)
	// Tests: odd offset 21
	// ============================================================
	ipv6Pkt, err := BuildIPv6UDPPacket(srcMAC, dstMAC, req.SrcIPv6, req.DstIPv6, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build IPv6 UDP packet (skipping): "+err.Error())
	} else {
		ipv6Checksums := []guest.ChecksumSpec{
			{ChecksumOffset: 60, HeaderStart: 54, HeaderLen: 0, IPHeaderOffset: 14}, // UDP checksum for IPv6
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: ipv6Pkt.Data, Length: uint16(len(ipv6Pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: ipv6Pkt.Offsets["ip6.hoplimit"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 32, End: 128}, PatternType: guest.ValuePatternTypeSequential}, // odd offset 21
				{ByteStart: ipv6Pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: ipv6Pkt.Offsets["ip6.src"] + 8, ByteSize: 8, ByteRange: guest.TemplateRange{Start: 1, End: 255}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 78, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: ipv6Checksums,
			Weight:    1,
		})
	}

	// ============================================================
	// ARP Variant (combined: Sender IP + Target IP + Operation)
	// ============================================================
	arpPkt, err := BuildARPPacket(srcMAC, req.SrcIP, req.DstIP, uint16(layers.ARPRequest))
	if err != nil {
		guest.Log(2, "failed to build ARP packet (skipping): "+err.Error())
	} else {
		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: arpPkt.Data, Length: uint16(len(arpPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: arpPkt.Offsets["arp.op"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 2}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: arpPkt.Offsets["arp.sender_ip"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0xC0A80001, End: 0xC0A800FE}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: arpPkt.Offsets["arp.target_ip"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0x0A000001, End: 0x0A0000FF}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 64}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // ARP has no checksum
			Weight:    1,
		})
	}

	// ============================================================
	// VLAN Tagged Variant (802.1Q) (combined: VLAN ID + Port)
	// ============================================================
	vlanPkt, err := BuildVLANTaggedPacket(srcMAC, dstMAC, 100, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build VLAN packet (skipping): "+err.Error())
	} else {
		vlanChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 28, HeaderStart: 18, HeaderLen: 20, IPHeaderOffset: 18}, // IP checksum
			{ChecksumOffset: 44, HeaderStart: 38, HeaderLen: 0, IPHeaderOffset: 18},  // UDP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: vlanPkt.Data, Length: uint16(len(vlanPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: vlanPkt.Offsets["vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: vlanPkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 68, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: vlanChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// QinQ (Double VLAN) Variant (combined: Outer + Inner VLAN + Port)
	// ============================================================
	qinqPkt, err := BuildQinQPacket(srcMAC, dstMAC, 100, 200, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build QinQ packet (skipping): "+err.Error())
	} else {
		qinqChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 32, HeaderStart: 22, HeaderLen: 20, IPHeaderOffset: 22}, // IP checksum
			{ChecksumOffset: 48, HeaderStart: 42, HeaderLen: 0, IPHeaderOffset: 22},  // UDP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: qinqPkt.Data, Length: uint16(len(qinqPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: qinqPkt.Offsets["outer_vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: qinqPkt.Offsets["inner_vlan.id"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 4094}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: qinqPkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 72, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: qinqChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// MPLS Variant (combined: Label + Port)
	// ============================================================
	mplsPkt, err := BuildMPLSPacket(srcMAC, dstMAC, 1000, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build MPLS packet (skipping): "+err.Error())
	} else {
		mplsChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 28, HeaderStart: 18, HeaderLen: 20, IPHeaderOffset: 18}, // IP checksum
			{ChecksumOffset: 44, HeaderStart: 38, HeaderLen: 0, IPHeaderOffset: 18},  // UDP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: mplsPkt.Data, Length: uint16(len(mplsPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: mplsPkt.Offsets["mpls.label"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 16 << 12, End: 1048575 << 12}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: mplsPkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 68, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: mplsChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// MPLS Stack Variant (3 labels + Port)
	// ============================================================
	mplsStackPkt, err := BuildMPLSStackPacket(srcMAC, dstMAC, []uint32{1000, 2000, 3000}, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build MPLS stack packet (skipping): "+err.Error())
	} else {
		// 3 labels = 12 bytes, IP at offset 26, UDP at 46
		mplsStackChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 36, HeaderStart: 26, HeaderLen: 20, IPHeaderOffset: 26},
			{ChecksumOffset: 52, HeaderStart: 46, HeaderLen: 0, IPHeaderOffset: 26},
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: mplsStackPkt.Data, Length: uint16(len(mplsStackPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: mplsStackPkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 76, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: mplsStackChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// LLDP Variant (TTL)
	// ============================================================
	lldpPkt, err := BuildLLDPPacket(srcMAC, "chassis1", "port1", 120)
	if err != nil {
		guest.Log(2, "failed to build LLDP packet (skipping): "+err.Error())
	} else {
		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: lldpPkt.Data, Length: uint16(len(lldpPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: lldpPkt.Offsets["lldp.ttl"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 64}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // LLDP has no checksum
			Weight:    1,
		})
	}

	// ============================================================
	// EAPoL Variant (Type at odd offset 15)
	// ============================================================
	eapolDstMAC := [6]byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x03} // PAE multicast
	eapolPkt, err := BuildEAPoLPacket(srcMAC, eapolDstMAC, layers.EAPOLTypeStart, nil)
	if err != nil {
		guest.Log(2, "failed to build EAPoL packet (skipping): "+err.Error())
	} else {
		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: eapolPkt.Data, Length: uint16(len(eapolPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: eapolPkt.Offsets["eapol.type"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 3}, PatternType: guest.ValuePatternTypeSequential}, // odd offset 15
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 64}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil,
			Weight:    1,
		})
	}

	// ============================================================
	// ICMPv4 Variant (combined: Type + Sequence)
	// ============================================================
	icmpPkt, err := BuildICMPv4Packet(srcMAC, dstMAC, req.SrcIP, req.DstIP, 8, 0, payload[:56]) // Echo request
	if err != nil {
		guest.Log(2, "failed to build ICMPv4 packet (skipping): "+err.Error())
	} else {
		icmpChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14}, // IP checksum
			{ChecksumOffset: 36, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},  // ICMP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: icmpPkt.Data, Length: uint16(len(icmpPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: icmpPkt.Offsets["icmp.type"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 18}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: icmpPkt.Offsets["icmp.seq"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 128}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: icmpChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// ICMPv6 Variant (Type)
	// ============================================================
	icmp6Pkt, err := BuildICMPv6Packet(srcMAC, dstMAC, req.SrcIPv6, req.DstIPv6, 128, 0, payload[:56]) // Echo request
	if err != nil {
		guest.Log(2, "failed to build ICMPv6 packet (skipping): "+err.Error())
	} else {
		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: icmp6Pkt.Data, Length: uint16(len(icmp6Pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: icmp6Pkt.Offsets["icmp6.type"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 128, End: 137}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 78, End: 78}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil, // ICMPv6 checksum handled differently
			Weight:    1,
		})
	}

	// ============================================================
	// TCP Variant (combined: Port + Flags + Sequence)
	// Tests: odd offset 47 (flags)
	// ============================================================
	tcpPkt, err := BuildTCPPacket(srcMAC, dstMAC, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, 0x02, payload[:100]) // SYN
	if err != nil {
		guest.Log(2, "failed to build TCP packet (skipping): "+err.Error())
	} else {
		tcpChecksums := []guest.ChecksumSpec{
			{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14}, // IP checksum
			{ChecksumOffset: 50, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},  // TCP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: tcpPkt.Data, Length: uint16(len(tcpPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: tcpPkt.Offsets["tcp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: tcpPkt.Offsets["tcp.flags"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 63}, PatternType: guest.ValuePatternTypeSequential}, // odd offset 47
				{ByteStart: tcpPkt.Offsets["tcp.seq"], ByteSize: 4, ByteRange: guest.TemplateRange{Start: 1, End: 0xFFFFFFFF}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: tcpChecksums,
			Weight:    1,
		})
	}

	// ============================================================
	// Raw Ethernet Frame Variant (combined: EtherType + Payload)
	// Tests: odd offset 15 (payload+1)
	// ============================================================
	rawPayload := make([]byte, 46)
	for i := range rawPayload {
		rawPayload[i] = byte(i)
	}
	rawPkt, err := BuildRawEthernetFrame(srcMAC, dstMAC, 0x9000, rawPayload) // Custom EtherType
	if err != nil {
		guest.Log(2, "failed to build raw Ethernet frame (skipping): "+err.Error())
	} else {
		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: rawPkt.Data, Length: uint16(len(rawPkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: rawPkt.Offsets["eth.type"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 0x0800, End: 0xFFFF}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: rawPkt.Offsets["payload"] + 1, ByteSize: 4, ByteRange: guest.TemplateRange{Start: 0, End: 0xFFFFFFFF}, PatternType: guest.ValuePatternTypeSequential}, // odd offset 15
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 64, End: 64}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: nil,
			Weight:    1,
		})
	}

	// ============================================================
	// SRv6 Variant (combined: SegmentsLeft + Port)
	// ============================================================
	srv6Segments := []string{
		"2001:db8:1::1",
		"2001:db8:2::1",
	}
	srv6Pkt, err := BuildSRv6Packet(srcMAC, dstMAC, req.SrcIPv6, req.DstIPv6, srv6Segments, req.SrcPort, req.DstPort, payload)
	if err != nil {
		guest.Log(2, "failed to build SRv6 packet (skipping): "+err.Error())
	} else {
		// SRH with 2 segments: 8 + 32 = 40 bytes
		// UDP offset: 54 + 40 = 94
		srv6Checksums := []guest.ChecksumSpec{
			{ChecksumOffset: 100, HeaderStart: 94, HeaderLen: 0, IPHeaderOffset: 14}, // UDP checksum
		}

		variants = append(variants, guest.PacketVariant{
			Base:   guest.BasePacket{Data: srv6Pkt.Data, Length: uint16(len(srv6Pkt.Data))},
			Params: []guest.VariableParams{
				{ByteStart: srv6Pkt.Offsets["srh.segments_left"], ByteSize: 1, ByteRange: guest.TemplateRange{Start: 0, End: 1}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: srv6Pkt.Offsets["udp.src"], ByteSize: 2, ByteRange: guest.TemplateRange{Start: 1024, End: 65535}, PatternType: guest.ValuePatternTypeSequential},
				{ByteStart: guest.ByteStartPacketLength, ByteSize: 0, ByteRange: guest.TemplateRange{Start: 110, End: 256}, PatternType: guest.ValuePatternTypeSequential},
			},
			Checksums: srv6Checksums,
			Weight:    1,
		})
	}

	// Create response
	res := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Variants: variants,
			Pattern:  guest.VariantSelectionModeMixed, // Weighted random selection
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
