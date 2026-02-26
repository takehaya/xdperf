package packets

import (
	"encoding/binary"
	"net"

	"github.com/takehaya/xdperf/pkg/guest"
)

func IPv4ToUint64(ip string) uint64 {
	v := net.ParseIP(ip).To4()
	if v == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(v))
}

// PacketInfo contains the built packet and offset information
type PacketInfo struct {
	Data    []byte
	Offsets map[string]uint64 // Named offsets for variable fields
}

// VariantConfig holds common parameters for building packet variants
type VariantConfig struct {
	SrcMAC   [6]byte
	DstMAC   [6]byte
	SrcIP    string
	DstIP    string
	SrcIPv6  string
	DstIPv6  string
	SrcPort  uint16
	DstPort  uint16
	Payload  []byte
}

// VariantResult contains one or more built variants or an error
type VariantResult struct {
	Variant  *guest.PacketVariant
	Variants []guest.PacketVariant
	Err      error
}

// VariantBuilder is a function that builds a packet variant
type VariantBuilder func(cfg VariantConfig) VariantResult
