package main

import "github.com/takehaya/xdperf/pkg/guest"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// GeneratorRequest is the JSON configuration accepted by the vxlan plugin.
//
// The plugin emits VXLAN (RFC 7348) traffic:
// outer Ethernet/IPv4/UDP(dst 4789) | VXLAN header (8) | inner Ethernet | inner
// IPv4 | inner UDP | payload.
//
// The outer UDP checksum is left 0 (the RFC 7348 default), so unlike GTP-U no
// outer UDP checksum spec is emitted; the inner IPv4 (and optionally inner UDP)
// checksums are recomputed by the data plane.
//
// Naming convention for varied fields: the VNI uses a `_start`/`_end` pair. When
// start == end the field is fixed (no variable param is emitted); when end >
// start the field is incremented sequentially per packet. The inner UDP source
// port, inner source IP, and outer UDP source port each have a boolean
// `vary_*` toggle that sweeps them sequentially up to their maximum.
type GeneratorRequest struct {
	// --- outer L2/L3 ---
	SrcIP        string `json:"src_ip" default:"10.0.0.1"`
	DstIP        string `json:"dst_ip" default:"10.0.0.2"`
	DstMac       string `json:"dst_mac" default:"ff:ff:ff:ff:ff:ff"`
	IsArpResolve bool   `json:"is_arp_resolve" default:"true"`
	// Outer UDP source port. VXLAN encapsulators usually derive this from a hash
	// of the inner frame for entropy; here it is fixed unless vary_outer_port is
	// set, in which case it sweeps from src_port up to 65535.
	SrcPort uint16 `json:"src_port" default:"0"`
	// Outer UDP destination port. The IANA-assigned VXLAN port is 4789.
	DstPort uint16 `json:"dst_port" default:"4789"`

	// --- VXLAN ---
	VNIStart uint32 `json:"vni_start" default:"100"`
	VNIEnd   uint32 `json:"vni_end" default:"100"`

	// --- inner L2 (the encapsulated Ethernet frame) ---
	InnerDstMac string `json:"inner_dst_mac" default:"02:00:00:00:01:02"`
	InnerSrcMac string `json:"inner_src_mac" default:"02:00:00:00:01:01"`

	// --- inner frame mode ---
	// inner_mode selects what is encapsulated: "ip" (default) builds an inner
	// Ethernet + IPv4 + UDP frame (92-byte minimum); "l2only" builds just an inner
	// Ethernet header + padding (64-byte minimum), for peak-pps testing. In
	// l2only mode the inner IP/port sweeps are ignored (there is no inner L3).
	InnerMode string `json:"inner_mode" default:"ip"`

	// --- inner L3/L4 ---
	// inner_udp_checksum controls the inner UDP checksum. Default false leaves it
	// 0 (disabled — legal over IPv4) and unrecomputed, which avoids the stale
	// inner-checksum artifact seen when mixing IMIX sizes. Set true to compute and
	// maintain it (required if you sweep the inner source port and want it valid).
	InnerUDPChecksum bool   `json:"inner_udp_checksum" default:"false"`
	InnerSrcIP       string `json:"inner_src_ip" default:"192.168.0.1"`
	InnerDstIP       string `json:"inner_dst_ip" default:"192.168.0.2"`
	InnerSrcPort     uint16 `json:"inner_src_port" default:"1024"`
	InnerDstPort     uint16 `json:"inner_dst_port" default:"5060"`

	// --- sweep toggles ---
	VaryInnerPort bool `json:"vary_inner_port" default:"false"`
	VaryInnerIP   bool `json:"vary_inner_ip" default:"false"`
	VaryOuterPort bool `json:"vary_outer_port" default:"false"`

	// --- IMIX (per-variant fixed frame sizes, weighted distribution) ---
	// imix_sizes are total on-wire frame lengths (including the 14-byte outer
	// Ethernet header, excluding FCS). Each entry becomes one base-packet variant;
	// entries smaller than the VXLAN header overhead are skipped.
	IMIXSizes   []int `json:"imix_sizes" default:"[128,768,1400]"`
	IMIXWeights []int `json:"imix_weights" default:"[7,2,1]"`

	// required param (injected by the host)
	guest.BaseGeneratorRequest
}
