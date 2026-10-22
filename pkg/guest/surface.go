package guest

// plugin_init
type GeneratorInitRequest struct {
	// Configuration data specific to the packet generation plugin.
	PluginConfig []byte `json:"plugin_config"`
}
type GeneratorInitResponse struct {
	// Indicates whether the initialization was successful.
	Success bool `json:"success"`
}

// plugin_process
// BaseGeneratorRequest represents the common parameters passed to a packet
// generation plugin.
type BaseGeneratorRequest struct {
	// TX worker frame limit, not the number of templates; 0 means unspecified.
	Count uint64 `json:"count" default:"1"`

	// Source MAC address.
	// Injected by the host based on the interface MAC.
	DeviceMacAddr []byte `json:"device_mac_addr"`

	// Network device name to send packets through.
	DeviceName string `json:"device_name"`
}

// GeneratorTemplateType represents the type of packet template.
type GeneratorTemplateType string

const (
	// Unknown template type.
	GeneratorTemplateTypeUnknown GeneratorTemplateType = ""

	// Raw template.
	// Pre-built packets are sent as they are.
	GeneratorTemplateTypeRaw GeneratorTemplateType = "raw"

	// Variable template.
	// Packets are generated on the host/XDP data-plane side using a template
	// and variable parameter sets.
	GeneratorTemplateTypeVariable GeneratorTemplateType = "variable"
)

// GeneratorProcessResponse is returned by a packet generation plugin to xdperf.
// TemplateType selects RawPacketTemplate or VariablePacketTemplate.
type GeneratorProcessResponse struct {
	// Template type.
	TemplateType GeneratorTemplateType `json:"template_type"`

	// Packet list for raw templates.
	// Used when TemplateType is raw.
	RawPacketTemplate []BasePacket `json:"raw_packet_template"`

	// Packet variation set for variable templates.
	// Used when TemplateType is variable.
	VariablePacketTemplate PacketVariantSet `json:"variable_packet_template"`
}

// VariantSelectionMode represents how to select among multiple packet variants.
type VariantSelectionMode string

const (
	// Unknown selection mode.
	VariantSelectionModeUnknown VariantSelectionMode = ""

	// Sequential selection.
	// Variants are selected in order, with counts based on weight.
	VariantSelectionModeSequential VariantSelectionMode = "sequential"

	// Mixed selection.
	// Variants are selected using weighted randomization.
	VariantSelectionModeMixed VariantSelectionMode = "mixed"
)

// ValuePatternType represents how parameter values vary within a variant.
type ValuePatternType string

const (
	// Unknown pattern type.
	ValuePatternTypeUnknown ValuePatternType = ""

	// Sequential pattern.
	// Values within the specified range are incremented sequentially.
	ValuePatternTypeSequential ValuePatternType = "sequential"

	// Mixed pattern.
	// Values are selected randomly within the range.
	ValuePatternTypeMixed ValuePatternType = "mixed"
)

// Special ByteStart value to indicate packet length modification
const ByteStartPacketLength uint64 = 0xFFFFFFFFFFFFFFFF

// VariableParams defines how a byte range varies. Packet variants evaluate it
// per diff entry. TCP flow variants evaluate it once per connection at startup,
// require an explicit base packet, and allow only inner source IP bytes.
// Byte sizes are 1, 2, 4, 6, or 8; values use network byte order.
type VariableParams struct {
	// Start offset of the target byte range from the beginning of the packet.
	// Use ByteStartPacketLength (0xFFFFFFFFFFFFFFFF) to vary packet length instead of byte content.
	ByteStart uint64 `json:"byte_start"`

	// Size of the byte range to modify.
	// Ignored when ByteStart is ByteStartPacketLength.
	ByteSize uint64 `json:"byte_size"`

	// Value range used for applying variations.
	// When ByteStart is ByteStartPacketLength, this specifies the packet length range.
	ByteRange TemplateRange `json:"byte_range"`

	// Pattern type used for value variation.
	PatternType ValuePatternType `json:"pattern_type"`
}

// TemplateRange represents a simple numerical range used when generating
// varying values.
type TemplateRange struct {
	// Start value.
	Start uint64 `json:"start"`

	// End value.
	End uint64 `json:"end"`
}

// PacketVariantSet represents a set of packet variants along with a pattern
// used to select among them. A set containing TCP flows requires mixed mode
// and at most 16 variants in total. Packet variants are optional.
type PacketVariantSet struct {
	// TCPPortBase is shared by all TCP groups; zero uses the default 10000.
	TCPPortBase uint16 `json:"tcp_port_base,omitempty"`

	// List of packet variants.
	Variants []PacketVariant `json:"variants"`

	// Selection mode for variants.
	// Sequential selects in order, mixed uses weighted randomization.
	Pattern VariantSelectionMode `json:"pattern"`
}

// ChecksumSpec defines where and how to calculate a checksum.
// Supported checksum types (auto-detected from packet content):
//   - IPv4 header checksum
//   - IPv4 transport: TCP, UDP
//   - IPv6 transport: TCP, UDP, ICMPv6
type ChecksumSpec struct {
	// Offset of the checksum field in the packet
	ChecksumOffset uint16 `json:"checksum_offset"`

	// Start offset of the header/data to checksum
	HeaderStart uint16 `json:"header_start"`

	// Length of the header (0 = compute from IP/transport length)
	HeaderLen uint16 `json:"header_len,omitempty"`

	// Offset of IP header (for pseudo-header calculation).
	// For IPv4 header checksum, set this equal to HeaderStart.
	IPHeaderOffset uint16 `json:"ip_header_offset"`
}

// PacketVariant is a packet template or a group of stateful TCP connections.
// A set containing TCP needs positive weights whose sum fits uint32. Weights allocate
// TX iterations, including TCP waits, rather than bytes or completed flows.
type PacketVariant struct {
	// Kind is empty or "packet" for packet generation, or "tcp_flow" for TCP.
	// Empty kind preserves the packet-only ABI; TCPFlow is required for tcp_flow.
	Kind    string          `json:"kind,omitempty"`
	TCPFlow *TCPFlowVariant `json:"tcp_flow,omitempty"`

	// Base contains bytes beginning at Ethernet. For TCP, it is optional when
	// Destination is supplied, and must end at the fixed inner TCP header.
	// TCP options, payload, source port, sequence/ACK numbers, flags, lengths,
	// windows and checksums are supplied or updated by the engine.
	Base BasePacket `json:"base_packet"`

	// Definitions of the variable byte regions within this packet.
	// Packet variants may use ByteStartPacketLength. TCP variants may vary
	// only inner source IP bytes and evaluate them once per flow at startup.
	Params []VariableParams `json:"variable_params"`

	// Checksum specifications for packet diffs. TCP variants must leave this empty.
	Checksums []ChecksumSpec `json:"checksums,omitempty"`

	// Weight used during variant selection.
	Weight uint32 `json:"weight"`
}

// BasePacket represents an Ethernet frame as raw bytes along with its valid
// length.
type BasePacket struct {
	// Raw bytes beginning at the Ethernet frame.
	// Typically base64 encoded when serialized to JSON.
	Data []byte `json:"data"`

	// Effective length of the data.
	Length uint16 `json:"length"`
}

// plugin_cleanup
type GeneratorCleanupRequest struct {
	// Configuration data specific to the packet generation plugin.
	PluginConfig []byte `json:"plugin_config"`
}
type GeneratorCleanupResponse struct {
	// Indicates whether the cleanup was successful.
	Success bool `json:"success"`
}

// TCPFlowVariant describes a group of static TCP connections sharing a target.
// The engine owns TCP sequence numbers, flags, windows and checksums.
// Destinations may differ between groups. Byte slices serialize as base64 JSON.
type TCPFlowVariant struct {
	// Connections repeats the Flows slots: nil = once, positive = total attempts,
	// zero = until --duration. Each attempt uses a fresh source port.
	Connections *uint32 `json:"connections,omitempty"`
	// Zero values use defaults: window 32, MSS sized for MTU, RTO 200ms.
	WindowSegs uint32 `json:"window_segs,omitempty"`
	MSS        uint16 `json:"mss,omitempty"`
	RTOMillis  uint32 `json:"rto_ms,omitempty"`
	// IPID is "flow" or "shared"; empty uses the default "flow".
	IPID string `json:"ip_id,omitempty"`

	// Timestamps offers TCP timestamps on SYN and uses them after negotiation.
	Timestamps bool `json:"timestamps,omitempty"`
	// PayloadPattern repeats at the 64-bit stream offset, including retransmits.
	// At most 256 bytes; empty or all-zero patterns use the zero-payload path.
	PayloadPattern []byte `json:"payload_pattern,omitempty"`
	// Encapsulation requires an explicit base packet and matching patch tables.
	Encapsulation *TCPEncapsulation `json:"encapsulation,omitempty"`
	// Destination is an IP literal and port; optional with Base, otherwise required.
	// When both are present, it must match the inner destination in Base.
	Destination string `json:"destination,omitempty"`
	// SynOptions and DataOptions contain static options. The engine prepends
	// MSS/WS on SYN, and reserves 12 bytes in both when Timestamps is true.
	// Total options cannot exceed 40 bytes; engine-owned kinds are rejected.
	SynOptions  []byte `json:"syn_options,omitempty"`
	DataOptions []byte `json:"data_options,omitempty"`
	// Flows are numbered in variant/array order and get globally unique source ports.
	Flows []TCPFlow `json:"flows"`
}

// TCPFlow.Bytes is a decimal uint64 string; zero requires --count or --duration.
type TCPFlow struct {
	Bytes string `json:"bytes"`
}

// TCPEncapsulation declares mutable outer-header fields. Offsets are absolute
// frame offsets; lengths contain Constant + inner TCP segment length.
// The base ends at the fixed TCP header and is at most 256 bytes. The host
// validates known tunnel structures and exact patch order/completeness.
// Limits: four outer IP layers, eight lengths, four outer IPv4 checksums,
// and four UDP checksums. Inner IP and TCP fields are always engine-owned.
type TCPEncapsulation struct {
	InnerL3Offset uint16            `json:"inner_l3_offset"`
	InnerL4Offset uint16            `json:"inner_l4_offset"`
	Lengths       []TCPLengthField  `json:"lengths"`
	IPv4Checksums []uint16          `json:"ipv4_checksums"`
	UDPChecksums  []TCPUDPChecksum  `json:"udp_checksums"`
	UDPSourcePort *TCPUDPSourcePort `json:"udp_source_port,omitempty"`
}

// TCPLengthField writes a uint16 length; Kind is ipv4, ipv6, udp, or gtpu.
type TCPLengthField struct {
	Offset   uint16 `json:"offset"`
	Kind     string `json:"kind"`
	Constant uint16 `json:"constant"`
}

// TCPUDPChecksum describes an outer UDP checksum. Offset points to the UDP
// header, IPOffset to its IP header; Mode is zero (IPv4 only) or lco.
type TCPUDPChecksum struct {
	Offset   uint16 `json:"offset"`
	IPOffset uint16 `json:"ip_offset"`
	Mode     string `json:"mode"` // zero (IPv4 only) or lco
}

// TCPUDPSourcePort selects Base + global flow index % Count for one outer UDP
// header. Offset points to its source port; the range must fit ports 1..65535.
type TCPUDPSourcePort struct {
	Offset uint16 `json:"offset"`
	Base   uint16 `json:"base"`
	Count  uint16 `json:"count"`
}
