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
	// Number of templates to generate.
	// Required by simpleudp as a common counter.
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
	// Packets are generated on the xdpcap side using a template and
	// variable parameter sets.
	GeneratorTemplateTypeVariable GeneratorTemplateType = "variable"
)

// GeneratorResponse represents the response returned from the packet
// generation plugin to simpleudp.
// Depending on TemplateType, either RawPacketTemplate or
// VariablePacketTemplate is used.
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

// VariableParams defines how a specific byte range in a packet should vary.
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
// used to select among them.
type PacketVariantSet struct {
	// List of packet variants.
	Variants []PacketVariant `json:"variants"`

	// Selection mode for variants.
	// Sequential selects in order, mixed uses weighted randomization.
	Pattern VariantSelectionMode `json:"pattern"`
}

// PacketVariant represents a base packet, the variable regions inside it,
// and a weight used for selection when patterns require it.
type PacketVariant struct {
	// Base packet containing raw bytes beginning from the Ethernet header.
	Base BasePacket `json:"base_packet"`

	// Definitions of the variable byte regions within this packet.
	// To vary packet length, include a VariableParams with ByteStart set to ByteStartPacketLength.
	Params []VariableParams `json:"variable_params"`

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
