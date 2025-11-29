package main

// plugin Request (configuration structure)
type GeneratorRequest struct {
	SrcIP       string `json:"src_ip" default:"192.168.1.1"`
	DstIP       string `json:"dst_ip" default:"192.168.1.2"`
	SrcPort     uint16 `json:"src_port" default:"1234"`
	DstPort     uint16 `json:"dst_port" default:"5678"`
	PayloadSize int    `json:"payload_size" default:"1024"`

	// required param
	Count         uint64 `json:"count" default:"1"`
	DeviceMacAddr []byte `json:"device_mac_addr"`
}

// plugin Response (output structure)
type GeneratorResponse struct {
	TemplateType           string                   `json:"template_type"` // e.g., "raw", "variable"
	RawPacketTemplate      []BasePacket             `json:"raw_packet_template"`
	VariablePacketTemplate []VariablePacketTemplate `json:"variable_packet_template"`
}

type TemplateRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}
type TemplateGeneraterParams struct {
	ByteStart   uint64        `json:"byte_start"`
	ByteSize    uint64        `json:"byte_size"`
	ByteRange   TemplateRange `json:"byte_range"`
	PatternType string        `json:"pattern_type"` // e.g., "sequential", "random"
}

type VariablePacketTemplate struct {
	BasePacket        BasePacket              `json:"base_packet"`
	TemplateGenerater TemplateGeneraterParams `json:"template_generater"`
}

type BasePacket struct {
	Data   []byte `json:"data"`
	Length uint16 `json:"length"`
}
