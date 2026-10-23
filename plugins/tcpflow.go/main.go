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
		Connections          *uint32 `json:"connections"`
		CPS                  uint32  `json:"cps"`
		PortReuseDelayMillis uint32  `json:"port_reuse_delay_ms"`
		WindowSegs           uint32  `json:"window_segs"`
		MSS                  uint16  `json:"mss"`
		RTOMillis            uint32  `json:"rto_ms"`
		IPID                 string  `json:"ip_id"`
		PortBase             uint16  `json:"port_base"`
		DstIP                string  `json:"dst_ip" default:"192.168.110.2"`
		TCPPort              uint16  `json:"tcp_port" default:"5201"`
		Flows                uint16  `json:"flows" default:"4"`
		Bytes                string  `json:"bytes" default:"65536"`
	}]()
	flows := make([]guest.TCPFlow, req.Flows)
	for i := range flows {
		flows[i] = guest.TCPFlow{Bytes: req.Bytes}
	}
	// Without base_packet, the host resolves the route and neighbor for TCP.
	goshim.PluginGeneratorProcessResponse(guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Pattern:     guest.VariantSelectionModeMixed,
			TCPPortBase: req.PortBase,
			Variants: []guest.PacketVariant{{
				Kind: "tcp_flow", Weight: 1,
				TCPFlow: &guest.TCPFlowVariant{
					Destination: net.JoinHostPort(req.DstIP, strconv.Itoa(int(req.TCPPort))),
					Flows:       flows,
					Connections: req.Connections,
					CPS:         req.CPS, PortReuseDelayMillis: req.PortReuseDelayMillis,
					WindowSegs: req.WindowSegs, MSS: req.MSS, RTOMillis: req.RTOMillis, IPID: req.IPID,
				},
			}},
		},
	})
	return 1
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(_, _, _, _ uint32) int32 {
	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{Success: true})
	return 0
}
