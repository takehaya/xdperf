package main

import "github.com/takehaya/xdperf/pkg/guest"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// plugin Request (configuration structure)
type GeneratorRequest struct {
	SrcIP        string `json:"src_ip" default:"192.168.1.1"`
	DstIP        string `json:"dst_ip" default:"192.168.1.2"`
	DstMac       string `json:"dst_mac" default:"ff:ff:ff:ff:ff:ff"`
	IsArpResolve bool   `json:"is_arp_resolve" default:"true"`
	SrcPort      uint16 `json:"src_port" default:"1234"`
	DstPort      uint16 `json:"dst_port" default:"5678"`
	PayloadSize  int    `json:"payload_size" default:"1024"`

	// Source-port sweep range for the variable template (inclusive). The sweep
	// width determines the number of distinct flows. Defaults keep the
	// historical 1024-1124 (~100 flows) behavior.
	SrcPortSweepStart uint16 `json:"src_port_sweep_start" default:"1024"`
	SrcPortSweepEnd   uint16 `json:"src_port_sweep_end" default:"1124"`

	// Optional outer 802.1Q VLAN tag. vlan_id 0 (the default) means no tag — it is
	// omitted entirely, so it can be dropped when not needed. vlan_pcp is the
	// 3-bit priority, only used when tagged.
	VLANID  uint16 `json:"vlan_id" default:"0"`
	VLANPCP uint8  `json:"vlan_pcp" default:"0"`

	// required param
	guest.BaseGeneratorRequest
}
