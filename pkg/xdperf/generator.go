package xdperf

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"

	"github.com/takehaya/xdperf/pkg/guest"
)

// maxBasePackets must match MAX_BASE_PACKETS in src/xdp_packet.h
const maxBasePackets = 16

// readBytesAt reads bytes from the packet at the given offset.
// Returns the bytes in a [16]byte array (network byte order).
// Supported sizes: 1, 2, 4, 6, 8 bytes.
func readBytesAt(data []byte, offset uint16, size uint8) ([16]byte, error) {
	var result [16]byte
	if int(offset)+int(size) > len(data) {
		return result, fmt.Errorf("offset %d + size %d exceeds data length %d", offset, size, len(data))
	}

	switch size {
	case 1, 2, 4, 6, 8:
		copy(result[:size], data[offset:offset+uint16(size)])
	default:
		return result, fmt.Errorf("unsupported size %d (only 1, 2, 4, 6, 8 are supported)", size)
	}
	return result, nil
}

// randomInRange returns a random value in [start, end].
// Returns error if range is invalid (start > end).
func randomInRange(start, end uint64) (uint64, error) {
	if end < start {
		return 0, fmt.Errorf("invalid range: start %d > end %d", start, end)
	}
	rangeSize := end - start + 1
	if rangeSize == 0 {
		// Full uint64 range (start=0, end=MaxUint64)
		return rand.Uint64(), nil
	}
	if rangeSize > math.MaxInt64 {
		return start + rand.Uint64()%rangeSize, nil
	}
	return start + uint64(rand.Int63n(int64(rangeSize))), nil
}

// valueToBytes converts a uint64 value to [16]byte in network byte order (big-endian).
// The value is placed in the first 'size' bytes.
// Supported sizes: 1, 2, 4, 8 (what fits in uint64).
func valueToBytes(value uint64, size uint8) ([16]byte, error) {
	var result [16]byte
	switch size {
	case 1:
		result[0] = byte(value)
	case 2:
		binary.BigEndian.PutUint16(result[:2], uint16(value))
	case 4:
		binary.BigEndian.PutUint32(result[:4], uint32(value))
	case 8:
		binary.BigEndian.PutUint64(result[:8], value)
	default:
		return result, fmt.Errorf("unsupported size %d (only 1, 2, 4, 8 are supported for uint64 values)", size)
	}
	return result, nil
}

// variantState tracks the sequential state for a single variant
type variantState struct {
	currentValues []uint64 // Current value for each param
}

// newVariantState creates a new state initialized from variant params
func newVariantState(params []guest.VariableParams) *variantState {
	state := &variantState{
		currentValues: make([]uint64, len(params)),
	}
	for i, p := range params {
		state.currentValues[i] = p.ByteRange.Start
	}
	return state
}

// generateSingleEntry generates a single diff entry from a variant using the given state
func generateSingleEntry(variant guest.PacketVariant, state *variantState, baseIdx uint8) (DiffEntry, error) {
	entry := DiffEntry{
		BaseIdx:   baseIdx,
		PacketLen: variant.Base.Length,
		Diffs:     make([]DiffValue, 0, len(variant.Params)),
	}

	for j, p := range variant.Params {
		// Check if this is a packet length variation
		if p.ByteStart == guest.ByteStartPacketLength {
			// Packet length uses uint64 range
			var value uint64
			var err error
			switch p.PatternType {
			case guest.ValuePatternTypeSequential:
				value = state.currentValues[j]
				state.currentValues[j]++
				if state.currentValues[j] > p.ByteRange.End {
					state.currentValues[j] = p.ByteRange.Start
				}
			case guest.ValuePatternTypeMixed:
				value, err = randomInRange(p.ByteRange.Start, p.ByteRange.End)
				if err != nil {
					return entry, fmt.Errorf("packet length range error: %w", err)
				}
			default:
				value = p.ByteRange.Start
			}
			if value > math.MaxUint16 {
				return entry, fmt.Errorf("packet length %d exceeds max uint16", value)
			}
			entry.PacketLen = uint16(value)
			continue
		}

		// Validate narrowing conversions
		if p.ByteStart > math.MaxUint16 {
			return entry, fmt.Errorf("param %d: byte_start %d exceeds max uint16", j, p.ByteStart)
		}
		if p.ByteSize > 8 {
			return entry, fmt.Errorf("param %d: byte_size %d exceeds max (8)", j, p.ByteSize)
		}

		// Read old value from base packet for bpf_csum_diff
		oldValue, err := readBytesAt(variant.Base.Data, uint16(p.ByteStart), uint8(p.ByteSize))
		if err != nil {
			return entry, fmt.Errorf("failed to read bytes at offset %d: %w", p.ByteStart, err)
		}

		var newValue [16]byte
		var value uint64
		switch p.PatternType {
		case guest.ValuePatternTypeSequential:
			value = state.currentValues[j]
			state.currentValues[j]++
			if state.currentValues[j] > p.ByteRange.End {
				state.currentValues[j] = p.ByteRange.Start
			}
		case guest.ValuePatternTypeMixed:
			var rangeErr error
			value, rangeErr = randomInRange(p.ByteRange.Start, p.ByteRange.End)
			if rangeErr != nil {
				return entry, fmt.Errorf("param %d range error: %w", j, rangeErr)
			}
		default:
			value = p.ByteRange.Start
		}
		newValue, err = valueToBytes(value, uint8(p.ByteSize))
		if err != nil {
			return entry, fmt.Errorf("failed to convert value to bytes for param %d: %w", j, err)
		}

		entry.Diffs = append(entry.Diffs, DiffValue{
			Offset:   uint16(p.ByteStart),
			Size:     uint8(p.ByteSize),
			OldValue: oldValue,
			NewValue: newValue,
		})
	}

	// Check if packet length changed from base
	entry.LenChanged = entry.PacketLen != variant.Base.Length

	return entry, nil
}

// generateDiffEntriesFromVariantSet generates diff entries from a variant set
// Returns base packets (one per variant) and diff entries with proper baseIdx
func generateDiffEntriesFromVariantSet(variantSet guest.PacketVariantSet, totalCount int) ([]BasePacketInfo, []DiffEntry, error) {
	if len(variantSet.Variants) == 0 {
		return nil, nil, nil
	}

	if len(variantSet.Variants) > maxBasePackets {
		return nil, nil, fmt.Errorf("too many variants: %d (max %d)", len(variantSet.Variants), maxBasePackets)
	}

	// Collect base packets (one per variant, no deduplication)
	bases := make([]BasePacketInfo, len(variantSet.Variants))
	for i, v := range variantSet.Variants {
		bases[i] = BasePacketInfo{
			Base:      v.Base,
			Checksums: v.Checksums,
		}
	}

	// Calculate total weight once (used by both Sequential and Mixed modes)
	var totalWeight uint32
	for _, v := range variantSet.Variants {
		totalWeight += v.Weight
	}
	if totalWeight == 0 {
		return nil, nil, fmt.Errorf("total weight is zero: all variants have zero weight")
	}

	// Pre-allocate slice to avoid reallocations during append
	allEntries := make([]DiffEntry, 0, totalCount)

	switch variantSet.Pattern {
	case guest.VariantSelectionModeSequential:
		// Distribute count across variants based on weight
		remaining := totalCount
		for i, v := range variantSet.Variants {
			var variantCount int
			if i == len(variantSet.Variants)-1 {
				variantCount = remaining
			} else {
				variantCount = int(float64(totalCount) * float64(v.Weight) / float64(totalWeight))
				remaining -= variantCount
			}

			if variantCount > 0 {
				state := newVariantState(v.Params)
				for j := 0; j < variantCount; j++ {
					entry, err := generateSingleEntry(v, state, uint8(i))
					if err != nil {
						return nil, nil, fmt.Errorf("variant %d entry %d: %w", i, j, err)
					}
					allEntries = append(allEntries, entry)
				}
			}
		}

	case guest.VariantSelectionModeMixed:
		// Create state for each variant (to maintain sequential values across selections)
		variantStates := make([]*variantState, len(variantSet.Variants))
		for i, v := range variantSet.Variants {
			variantStates[i] = newVariantState(v.Params)
		}

		// Generate entries with weighted random variant selection
		for i := 0; i < totalCount; i++ {
			// Select variant based on weight
			r := uint32(rand.Int31n(int32(totalWeight)))
			var cumulative uint32
			selectedIdx := 0
			for j, v := range variantSet.Variants {
				cumulative += v.Weight
				if r < cumulative {
					selectedIdx = j
					break
				}
			}

			// Generate single entry from selected variant using its state
			entry, err := generateSingleEntry(variantSet.Variants[selectedIdx], variantStates[selectedIdx], uint8(selectedIdx))
			if err != nil {
				return nil, nil, fmt.Errorf("mixed mode entry %d (variant %d): %w", i, selectedIdx, err)
			}
			allEntries = append(allEntries, entry)
		}

	default:
		// Default to first variant
		state := newVariantState(variantSet.Variants[0].Params)
		for i := 0; i < totalCount; i++ {
			entry, err := generateSingleEntry(variantSet.Variants[0], state, 0)
			if err != nil {
				return nil, nil, fmt.Errorf("default mode entry %d: %w", i, err)
			}
			allEntries = append(allEntries, entry)
		}
	}

	return bases, allEntries, nil
}

// GenerateVariableEntries generates packet entries from a variable template response
func GenerateVariableEntries(response guest.GeneratorProcessResponse, count int) ([]BasePacketInfo, []DiffEntry, error) {
	if response.TemplateType != guest.GeneratorTemplateTypeVariable {
		return nil, nil, nil
	}

	return generateDiffEntriesFromVariantSet(response.VariablePacketTemplate, count)
}

// GenerateRawEntries generates packet entries from raw packets
// Raw packets become base packets with diff_count=0
func GenerateRawEntries(packets []guest.BasePacket, count int) ([]BasePacketInfo, []DiffEntry, error) {
	if len(packets) == 0 {
		return nil, nil, nil
	}

	if len(packets) > maxBasePackets {
		return nil, nil, fmt.Errorf("too many raw packets: %d (max %d)", len(packets), maxBasePackets)
	}

	// Each raw packet gets its own base (no deduplication)
	bases := make([]BasePacketInfo, len(packets))
	for i, pkt := range packets {
		bases[i] = BasePacketInfo{
			Base:      pkt,
			Checksums: nil, // Raw packets have pre-computed checksums
		}
	}

	// Create diff entries with diff_count=0 (no modifications needed)
	// Round-robin through raw packets to fill count entries
	entries := make([]DiffEntry, count)
	for i := 0; i < count; i++ {
		pktIdx := i % len(packets)
		entries[i] = DiffEntry{
			BaseIdx:    uint8(pktIdx),
			PacketLen:  packets[pktIdx].Length,
			LenChanged: false,
			Diffs:      nil, // No diffs for raw packets
		}
	}

	return bases, entries, nil
}
