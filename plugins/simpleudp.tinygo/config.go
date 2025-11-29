package main

import "github.com/takehaya/xdperf/pkg/guest"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// plugin Request (configuration structure)
type GeneratorRequest struct {
	SrcIP       string `json:"src_ip" default:"192.168.1.1"`
	DstIP       string `json:"dst_ip" default:"192.168.1.2"`
	SrcPort     uint16 `json:"src_port" default:"1234"`
	DstPort     uint16 `json:"dst_port" default:"5678"`
	PayloadSize int    `json:"payload_size" default:"1024"`
	// required param
	guest.BaseGeneratorRequest
}
