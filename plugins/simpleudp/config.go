package main

// plugin Request (configuration structure)
type GeneratorRequest struct {
	SrcIP       string `json:"src_ip" default:"192.168.1.1"`
	DstIP       string `json:"dst_ip" default:"192.168.1.2"`
	SrcPort     uint16 `json:"src_port" default:"1234"`
	DstPort     uint16 `json:"dst_port" default:"5678"`
	PayloadSize int    `json:"payload_size" default:"1024"`

	// required param
	Count         uint64  `json:"count" default:"1"`
	DeviceMacAddr [6]byte `json:"device_mac_addr"`
}

// plugin Response (output structure)
type GeneratorResponse struct {
	Template PacketTemplate `json:"template"`
	Metadata Metadata       `json:"metadata"`
}

type PacketTemplate struct {
	BasePacket BasePacket `json:"base_packet"`
}

type BasePacket struct {
	Data   string `json:"data"`
	Length uint16 `json:"length"`
}

type Metadata struct {
	PacketCount uint64   `json:"packet_count"`
	RatePPS     uint64   `json:"rate_pps"`
	Tags        []string `json:"tags"`
}
