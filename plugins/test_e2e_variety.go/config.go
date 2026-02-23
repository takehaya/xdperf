package main

import (
	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/plugins/test_e2e_variety/packets"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// GeneratorRequest is the plugin configuration structure
type GeneratorRequest struct {
	SrcIP        string `json:"src_ip" default:"192.168.1.1"`
	DstIP        string `json:"dst_ip" default:"192.168.1.2"`
	SrcIPv6      string `json:"src_ipv6" default:"2001:db8::1"`
	DstIPv6      string `json:"dst_ipv6" default:"2001:db8::2"`
	DstMac       string `json:"dst_mac" default:"ff:ff:ff:ff:ff:ff"`
	IsArpResolve bool   `json:"is_arp_resolve" default:"true"`
	SrcPort      uint16 `json:"src_port" default:"1234"`
	DstPort      uint16 `json:"dst_port" default:"5678"`
	PayloadSize  int    `json:"payload_size" default:"1024"`

	// Protocol selection - list of protocols to include
	// Empty or "all" means all protocols. Available protocols:
	// ipv4_udp, ipv6_udp, vlan, qinq, icmpv4, icmpv6, tcp, raw, srv6,
	// arp, eapol, lldp, l2vpn, l3vpn, l2vpn_srv6, l3vpn_srv6
	Protocols []string `json:"protocols"`

	// required param
	guest.BaseGeneratorRequest
}

// GetProtocolsToInclude returns the list of protocols to include
func (r *GeneratorRequest) GetProtocolsToInclude() []string {
	if len(r.Protocols) == 0 {
		return packets.AllProtocols()
	}
	for _, p := range r.Protocols {
		if p == "all" {
			return packets.AllProtocols()
		}
	}
	return r.Protocols
}
