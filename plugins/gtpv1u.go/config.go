package main

import "github.com/takehaya/xdperf/pkg/guest"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// GeneratorRequest is the JSON configuration accepted by the gtpv1u plugin.
//
// The plugin emits GTPv1-U (G-PDU, message type 0xFF) data-plane traffic:
// outer Ethernet/IPv4/UDP(dst 2152) | GTP-U header | inner IPv4/UDP | payload.
// When enable_psc is true the GTP-U header carries a 5G PDU Session Container
// extension header (type 0x85) so the QFI can be exercised.
//
// Naming convention for varied fields: TEID and QFI both use a `_start`/`_end`
// pair. When start == end the field is fixed (no variable param is emitted);
// when end > start the field is incremented sequentially per packet.
type GeneratorRequest struct {
	// --- outer L2/L3 ---
	SrcIP        string `json:"src_ip" default:"10.0.0.1"`
	DstIP        string `json:"dst_ip" default:"10.0.0.2"`
	DstMac       string `json:"dst_mac" default:"ff:ff:ff:ff:ff:ff"`
	IsArpResolve bool   `json:"is_arp_resolve" default:"true"`
	// Outer UDP source port. GTP-U uses 2152 as the destination port (fixed);
	// real deployments often use 2152 as the source port as well.
	SrcPort uint16 `json:"src_port" default:"2152"`

	// --- GTP-U ---
	TEIDStart uint32 `json:"teid_start" default:"1"`
	TEIDEnd   uint32 `json:"teid_end" default:"1"`
	EnablePSC bool   `json:"enable_psc" default:"true"`
	EnableSeq bool   `json:"enable_seq" default:"false"`
	// PDU Session Container PDU type: "dl" (downlink) or "ul" (uplink).
	PDUType  string `json:"pdu_type" default:"dl"`
	RQI      bool   `json:"rqi" default:"false"`
	QFIStart uint8  `json:"qfi_start" default:"9"`
	QFIEnd   uint8  `json:"qfi_end" default:"9"`

	// --- inner T-PDU ---
	// inner_proto selects the inner transport: "udp" (default) or "icmp" (an
	// ICMPv4 echo request). inner_src_port/inner_dst_port/vary_inner_port apply
	// to "udp" only.
	InnerProto string `json:"inner_proto" default:"udp"`
	// inner_udp_checksum controls the inner UDP checksum (udp only). Default false
	// leaves it 0 (disabled — legal over IPv4) and unrecomputed, which avoids the
	// stale inner-checksum artifact seen when mixing IMIX sizes. Set true to
	// compute and maintain it.
	InnerUDPChecksum bool   `json:"inner_udp_checksum" default:"false"`
	InnerSrcIP       string `json:"inner_src_ip" default:"192.168.0.1"`
	InnerDstIP       string `json:"inner_dst_ip" default:"192.168.0.2"`
	InnerSrcPort     uint16 `json:"inner_src_port" default:"1024"`
	InnerDstPort     uint16 `json:"inner_dst_port" default:"5060"`
	VaryInnerPort    bool   `json:"vary_inner_port" default:"false"`

	// --- IMIX (per-variant fixed frame sizes, weighted distribution) ---
	// imix_sizes are total on-wire frame lengths (including the 14-byte Ethernet
	// header, excluding FCS). Each entry becomes one base-packet variant; entries
	// smaller than the GTP-U header overhead are skipped.
	IMIXSizes   []int `json:"imix_sizes" default:"[128,768,1400]"`
	IMIXWeights []int `json:"imix_weights" default:"[7,2,1]"`

	// required param (injected by the host)
	guest.BaseGeneratorRequest
}
