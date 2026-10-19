package main

import (
	"fmt"
	"net"

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
		SrcIP            string                  `json:"src_ip" default:"192.168.110.1"`
		DstIP            string                  `json:"dst_ip" default:"192.168.110.2"`
		DstMAC           string                  `json:"dst_mac" default:"02:00:00:00:00:02"`
		TCPPort          int                     `json:"tcp_port" default:"5201"`
		UDPPort          uint16                  `json:"udp_port" default:"5353"`
		SmallBytes       string                  `json:"small_bytes" default:"65536"`
		LargeBytes       string                  `json:"large_bytes" default:"67108864"`
		PacketWeight     uint32                  `json:"packet_weight" default:"3"`
		TCPWeight        uint32                  `json:"tcp_weight" default:"1"`
		TCPBase          guest.BasePacket        `json:"tcp_base"`
		SynOptions       []byte                  `json:"syn_options"`
		DataOptions      []byte                  `json:"data_options"`
		TCPEncapsulation *guest.TCPEncapsulation `json:"tcp_encapsulation"`
	}]()
	mac, err := net.ParseMAC(req.DstMAC)
	if err != nil || len(mac) != 6 || len(req.DeviceMacAddr) != 6 {
		return -1
	}
	// DNS query: example.com IN A, padded to keep the frame above 64 bytes.
	payload := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	packet, off, err := BuildSamplePacket([6]byte(req.DeviceMacAddr), [6]byte(mac), 0, 0, req.SrcIP, req.DstIP, 53000, req.UDPPort, payload)
	if err != nil {
		return -2
	}
	destination := net.JoinHostPort(req.DstIP, fmt.Sprint(req.TCPPort))
	if len(req.TCPBase.Data) != 0 {
		destination = ""
	}
	flows := []guest.TCPFlow{{Bytes: req.SmallBytes}, {Bytes: req.SmallBytes}, {Bytes: req.SmallBytes}, {Bytes: req.LargeBytes}}
	goshim.PluginGeneratorProcessResponse(guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{Pattern: guest.VariantSelectionModeMixed, Variants: []guest.PacketVariant{
			{Kind: "packet", Weight: req.PacketWeight, Base: guest.BasePacket{Data: packet, Length: uint16(len(packet))}, Checksums: guest.IPv4UDPChecksumSpecs(uint16(off) - guest.IPv4HeaderLen)},
			{Kind: "tcp_flow", Weight: req.TCPWeight, Base: req.TCPBase, TCPFlow: &guest.TCPFlowVariant{Destination: destination, SynOptions: req.SynOptions, DataOptions: req.DataOptions, Encapsulation: req.TCPEncapsulation, Flows: flows}},
		}},
	})
	return 1
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(_, _, _, _ uint32) int32 {
	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{Success: true})
	return 0
}
