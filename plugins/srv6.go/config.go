package main

import "github.com/takehaya/xdperf/pkg/guest"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// GeneratorRequest is the JSON configuration accepted by the srv6 plugin.
//
// The plugin emits SRv6 (RFC 8754) traffic: outer Ethernet/IPv6 | SRH | inner
// packet. The `mode` field selects the encapsulation:
//   - "l3vpn_ipv4" (default): inner IPv4/UDP (SRH next header 4, End.DX4/DT4-style)
//   - "l2vpn_eth": inner Ethernet + IPv4/UDP (SRH next header 143, End.DX2-style)
//   - "ipv6": inner IPv6/UDP (SRH next header 41, End.DX6/DT6-style)
//
// The outer IPv6 header has no checksum; the data plane recomputes the inner
// IPv4 header and inner UDP checksums (l3vpn_ipv4/l2vpn_eth) or the inner UDP
// checksum over the IPv6 pseudo header (ipv6 mode). The inner UDP checksum is
// always computed — over IPv6 a zero UDP checksum is illegal (RFC 8200).
//
// Naming convention for varied fields: the flow label and SRH tag use
// `_start`/`_end` pairs. When start == end the field is fixed (no variable
// param is emitted); when end > start the field is incremented sequentially per
// packet. The inner ports and inner source IP each have a boolean `vary_*`
// toggle that sweeps them sequentially up to their maximum.
type GeneratorRequest struct {
	// --- outer L2 ---
	DstMac string `json:"dst_mac" default:"ff:ff:ff:ff:ff:ff"`
	// is_arp_resolve resolves the outer destination MAC via NDP for the outer
	// destination IPv6 address.
	IsArpResolve bool `json:"is_arp_resolve" default:"true"`

	// --- outer IPv6 ---
	SrcIP string `json:"src_ip" default:"2001:db8::1"`
	// dst_ip is the outer IPv6 destination. Empty (the default) uses
	// segments[0] — the first segment to visit.
	DstIP        string `json:"dst_ip" default:""`
	TrafficClass uint8  `json:"traffic_class" default:"0"`
	// 20-bit IPv6 flow label sweep range.
	FlowLabelStart uint32 `json:"flow_label_start" default:"0"`
	FlowLabelEnd   uint32 `json:"flow_label_end" default:"0"`

	// --- SRH ---
	Mode string `json:"mode" default:"l3vpn_ipv4"`
	// segments is the SID list in visiting order: segments[0] is the first
	// segment to visit (the initial outer destination when dst_ip is empty) and
	// the last element is the final segment. Stored reversed in the SRH per
	// RFC 8754 (Segment List[0] holds the final segment). 1..127 IPv6 addresses
	// (the 8-bit Hdr Ext Len limit).
	Segments []string `json:"segments" default:"[\"2001:db8:100::1\"]"`
	// 16-bit SRH tag sweep range.
	SRHTagStart uint16 `json:"srh_tag_start" default:"0"`
	SRHTagEnd   uint16 `json:"srh_tag_end" default:"0"`

	// --- inner L2 (l2vpn_eth mode only) ---
	InnerDstMac string `json:"inner_dst_mac" default:"02:00:00:00:01:02"`
	InnerSrcMac string `json:"inner_src_mac" default:"02:00:00:00:01:01"`

	// --- inner L3/L4 ---
	// IPv4 inner addresses (l3vpn_ipv4 / l2vpn_eth modes).
	InnerSrcIP string `json:"inner_src_ip" default:"192.168.0.1"`
	InnerDstIP string `json:"inner_dst_ip" default:"192.168.0.2"`
	// IPv6 inner addresses (ipv6 mode). Kept separate from the IPv4 pair so
	// every mode works with the zero config.
	InnerSrcIP6  string `json:"inner_src_ip6" default:"fd00::1"`
	InnerDstIP6  string `json:"inner_dst_ip6" default:"fd00::2"`
	InnerSrcPort uint16 `json:"inner_src_port" default:"1024"`
	InnerDstPort uint16 `json:"inner_dst_port" default:"5060"`

	// --- sweep toggles ---
	VaryInnerSrcPort bool `json:"vary_inner_src_port" default:"false"`
	VaryInnerDstPort bool `json:"vary_inner_dst_port" default:"false"`
	// vary_inner_ip sweeps the inner source IP: the full 4 bytes in the IPv4
	// modes, the last hextet (2 bytes) in ipv6 mode.
	VaryInnerIP bool `json:"vary_inner_ip" default:"false"`

	// --- IMIX (per-variant fixed frame sizes, weighted distribution) ---
	// imix_sizes are total on-wire frame lengths (including the 14-byte outer
	// Ethernet header, excluding FCS). Each entry becomes one base-packet
	// variant; entries smaller than the header overhead are skipped. The default
	// starts at 256 because the minimum depends on the mode and segment count
	// (106..126 with one segment, +16 per extra segment).
	IMIXSizes   []int `json:"imix_sizes" default:"[256,768,1400]"`
	IMIXWeights []int `json:"imix_weights" default:"[7,2,1]"`

	// required param (injected by the host)
	guest.BaseGeneratorRequest
}
