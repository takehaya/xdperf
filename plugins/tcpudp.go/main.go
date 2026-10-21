package main

import (
	"net"
	"strconv"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
)

func main() {}

//go:wasmexport plugin_init
func plugin_init(_, _, _, _ uint32) int32 {
	goshim.PluginGeneratorInitResponse(guest.GeneratorInitResponse{Success: true})
	return 1
}

//go:wasmexport plugin_process
func plugin_process(_, _, _, _ uint32) int32 {
	req := goshim.PluginGeneratorProcessRequest[struct {
		guest.BaseGeneratorRequest
		SrcIP        string `json:"src_ip" default:"192.168.110.1"`
		DstIP        string `json:"dst_ip" default:"192.168.110.2"`
		DstMAC       string `json:"dst_mac" default:"02:00:00:00:00:02"`
		TCPPort      uint16 `json:"tcp_port" default:"5201"`
		UDPPort      uint16 `json:"udp_port" default:"5201"`
		PacketWeight uint32 `json:"packet_weight" default:"3"`
		TCPWeight    uint32 `json:"tcp_weight" default:"1"`
	}]()
	mac, err := net.ParseMAC(req.DstMAC)
	if err != nil || len(mac) != 6 || len(req.DeviceMacAddr) != 6 {
		return -1
	}
	packet, err := buildUDPPacket(req.DeviceMacAddr, mac, req.SrcIP, req.DstIP, req.UDPPort)
	if err != nil {
		return -2
	}
	goshim.PluginGeneratorProcessResponse(guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Pattern: guest.VariantSelectionModeMixed,
			Variants: []guest.PacketVariant{
				{
					Kind: "packet", Weight: req.PacketWeight,
					Base:      guest.BasePacket{Data: packet, Length: uint16(len(packet))},
					Checksums: guest.IPv4UDPChecksumSpecs(14),
				},
				{
					Kind: "tcp_flow", Weight: req.TCPWeight,
					TCPFlow: &guest.TCPFlowVariant{
						Destination: net.JoinHostPort(req.DstIP, strconv.Itoa(int(req.TCPPort))),
						Flows:       []guest.TCPFlow{{Bytes: "65536"}},
					},
				},
			},
		},
	})
	return 1
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(_, _, _, _ uint32) int32 {
	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{Success: true})
	return 0
}
