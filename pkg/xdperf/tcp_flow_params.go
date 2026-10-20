package xdperf

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

// Flow parameters deliberately allow only bytes of the inner source address.
// This keeps structural fields, engine fields and outer checksum inputs fixed.
func validateTCPFlowParams(v guest.PacketVariant) error {
	if len(v.Params) == 0 {
		return nil
	}
	if len(v.Base.Data) == 0 {
		return fmt.Errorf("TCP variable_params require base_packet")
	}
	t, err := parseTCPVariant(v)
	if err != nil {
		return err
	}
	start, size := uint64(t.l3Off)+12, uint64(4)
	if t.ipVersion == 6 {
		start, size = uint64(t.l3Off)+8, 16
	}
	used := make(map[uint64]bool)
	for _, p := range v.Params {
		if !isAllowedByteSize(int(p.ByteSize)) || p.ByteSize > 8 || p.ByteStart < start || p.ByteStart > start+size || p.ByteSize > start+size-p.ByteStart {
			return fmt.Errorf("TCP variable_params support only inner source IP bytes (offset %d, length %d)", start, size)
		}
		if p.ByteRange.Start > p.ByteRange.End || (p.ByteSize < 8 && p.ByteRange.End >= uint64(1)<<(8*p.ByteSize)) {
			return fmt.Errorf("TCP variable_params value range does not fit byte_size")
		}
		if p.PatternType != guest.ValuePatternTypeSequential && p.PatternType != guest.ValuePatternTypeMixed {
			return fmt.Errorf("TCP variable_params require sequential or mixed pattern_type")
		}
		for i := p.ByteStart; i < p.ByteStart+p.ByteSize; i++ {
			if used[i] {
				return fmt.Errorf("overlapping TCP variable_params")
			}
			used[i] = true
		}
	}
	return nil
}

func nextTCPFlowVariant(v guest.PacketVariant, state *variantState) (guest.PacketVariant, error) {
	v.Base.Data = append([]byte(nil), v.Base.Data...)
	for j, p := range v.Params {
		value := state.currentValues[j]
		if p.PatternType == guest.ValuePatternTypeMixed {
			var err error
			value, err = randomInRange(p.ByteRange.Start, p.ByteRange.End)
			if err != nil {
				return v, err
			}
		} else if value == p.ByteRange.End || value == math.MaxUint64 {
			state.currentValues[j] = p.ByteRange.Start
		} else {
			state.currentValues[j]++
		}
		b, err := valueToBytes(value, uint8(p.ByteSize))
		if err != nil {
			return v, err
		}
		copy(v.Base.Data[int(p.ByteStart):int(p.ByteStart+p.ByteSize)], b[:p.ByteSize])
	}
	// Validate the actual address, including unspecified/multicast results.
	if _, err := parseTCPVariant(v); err != nil {
		return v, err
	}
	return v, nil
}

func tcpFlowOptions(f *guest.TCPFlowVariant, syn bool) ([]byte, error) {
	input := f.DataOptions
	if syn {
		input = f.SynOptions
	}
	b, err := tcpStaticOptions(input, syn)
	if err != nil {
		return nil, err
	}
	limit := 40
	if syn {
		limit -= tcpSynOptLen
	}
	if f.Timestamps {
		limit -= 12
	}
	if len(b) > limit {
		return nil, fmt.Errorf("TCP options including timestamps exceed 40 bytes")
	}
	return b, nil
}

func tcpPayload(pattern []byte) (coreelf.BpfTcpPayload, error) {
	var p coreelf.BpfTcpPayload
	if len(pattern) > 256 {
		return p, fmt.Errorf("TCP payload_pattern exceeds 256 bytes")
	}
	nonzero := false
	for _, b := range pattern {
		nonzero = nonzero || b != 0
	}
	if !nonzero {
		return p, nil
	}
	n := len(pattern)
	if n%2 != 0 {
		n *= 2
	}
	p.Period = uint16(n)
	for i := 0; i < n; i++ {
		p.Bytes[i] = pattern[i%len(pattern)]
	}
	for i := 0; i < n/2; i++ {
		p.Sums[i+1] = p.Sums[i] + uint32(binary.BigEndian.Uint16(p.Bytes[2*i:]))
	}
	return p, nil
}

func (g mixedGroup) templateID(flow uint32, group int) uint32 {
	if len(g.variant.Params) != 0 {
		return g.templateFirst + flow - g.first
	}
	return uint32(group)
}

func (p *mixedPlan) templateIDs() []uint32 {
	var ids []uint32
	for j, g := range p.groups {
		n := uint32(1)
		if len(g.variant.Params) != 0 {
			n = g.count
		}
		for i := uint32(0); i < n; i++ {
			ids = append(ids, g.templateID(g.first+i, j))
		}
	}
	return ids
}
