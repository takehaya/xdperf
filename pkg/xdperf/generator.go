package xdperf

import (
	"encoding/binary"
	"math/rand"

	"github.com/takehaya/xdperf/pkg/guest"
)

// readValueAt reads a value from the packet at the given offset
func readValueAt(data []byte, offset uint16, size uint8) uint32 {
	if int(offset)+int(size) > len(data) {
		return 0
	}

	switch size {
	case 1:
		return uint32(data[offset])
	case 2:
		return uint32(binary.BigEndian.Uint16(data[offset:]))
	case 4:
		return binary.BigEndian.Uint32(data[offset:])
	}
	return 0
}

// variantState tracks the sequential state for a single variant
type variantState struct {
	currentValues []uint64 // Current value for each param (for sequential patterns)
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
func generateSingleEntry(variant guest.PacketVariant, state *variantState, baseIdx uint8) DiffEntry {
	entry := DiffEntry{
		BaseIdx:   baseIdx,
		PacketLen: variant.Base.Length,
		Diffs:     make([]DiffValue, 0, len(variant.Params)),
	}

	for j, p := range variant.Params {
		var value uint64

		switch p.PatternType {
		case guest.ValuePatternTypeSequential:
			value = state.currentValues[j]
			// Increment for next iteration
			state.currentValues[j]++
			if state.currentValues[j] > p.ByteRange.End {
				state.currentValues[j] = p.ByteRange.Start
			}
		case guest.ValuePatternTypeMixed:
			// Random value within range
			rangeSize := p.ByteRange.End - p.ByteRange.Start + 1
			value = p.ByteRange.Start + uint64(rand.Int63n(int64(rangeSize)))
		default:
			value = p.ByteRange.Start
		}

		// Check if this is a packet length variation
		if p.ByteStart == guest.ByteStartPacketLength {
			entry.PacketLen = uint16(value)
		} else {
			// Regular byte modification
			// Read old value from base packet for bpf_csum_diff
			oldValue := readValueAt(variant.Base.Data, uint16(p.ByteStart), uint8(p.ByteSize))
			entry.Diffs = append(entry.Diffs, DiffValue{
				Offset:   uint16(p.ByteStart),
				Size:     uint8(p.ByteSize),
				OldValue: oldValue,
				NewValue: uint32(value),
			})
		}
	}

	// Check if packet length changed from base
	entry.LenChanged = entry.PacketLen != variant.Base.Length

	return entry
}

// basePacketKey creates a unique key for a base packet (for deduplication)
func basePacketKey(base guest.BasePacket) string {
	return string(base.Data[:base.Length])
}

// collectUniqueBases collects unique base packets from variants and returns
// the base info list and a mapping from variant index to base index
func collectUniqueBases(variants []guest.PacketVariant) ([]BasePacketInfo, map[int]uint8) {
	bases := []BasePacketInfo{}
	variantToBaseIdx := make(map[int]uint8)
	baseKeyToIdx := make(map[string]uint8)

	for i, v := range variants {
		key := basePacketKey(v.Base)

		if idx, exists := baseKeyToIdx[key]; exists {
			// Reuse existing base
			variantToBaseIdx[i] = idx
		} else {
			// New unique base
			idx := uint8(len(bases))
			baseKeyToIdx[key] = idx
			variantToBaseIdx[i] = idx
			bases = append(bases, BasePacketInfo{
				Base:      v.Base,
				Checksums: v.Checksums,
			})
		}
	}

	return bases, variantToBaseIdx
}

// generateDiffEntriesFromVariantSet generates diff entries from a variant set
// Returns unique base packets and diff entries with proper baseIdx
func generateDiffEntriesFromVariantSet(variantSet guest.PacketVariantSet, totalCount int) ([]BasePacketInfo, []DiffEntry) {
	if len(variantSet.Variants) == 0 {
		return nil, nil
	}

	// Collect unique base packets
	bases, variantToBaseIdx := collectUniqueBases(variantSet.Variants)

	var allEntries []DiffEntry

	switch variantSet.Pattern {
	case guest.VariantSelectionModeSequential:
		// Calculate total weight
		var totalWeight uint32
		for _, v := range variantSet.Variants {
			totalWeight += v.Weight
		}

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
				baseIdx := variantToBaseIdx[i]
				state := newVariantState(v.Params)
				for j := 0; j < variantCount; j++ {
					entry := generateSingleEntry(v, state, baseIdx)
					allEntries = append(allEntries, entry)
				}
			}
		}

	case guest.VariantSelectionModeMixed:
		// Calculate total weight for weighted random selection
		var totalWeight uint32
		for _, v := range variantSet.Variants {
			totalWeight += v.Weight
		}

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
			baseIdx := variantToBaseIdx[selectedIdx]
			entry := generateSingleEntry(variantSet.Variants[selectedIdx], variantStates[selectedIdx], baseIdx)
			allEntries = append(allEntries, entry)
		}

	default:
		// Default to first variant
		baseIdx := variantToBaseIdx[0]
		state := newVariantState(variantSet.Variants[0].Params)
		for i := 0; i < totalCount; i++ {
			entry := generateSingleEntry(variantSet.Variants[0], state, baseIdx)
			allEntries = append(allEntries, entry)
		}
	}

	return bases, allEntries
}

// GenerateVariableEntries generates packet entries from a variable template response
func GenerateVariableEntries(response guest.GeneratorProcessResponse, count int) ([]BasePacketInfo, []DiffEntry, error) {
	if response.TemplateType != guest.GeneratorTemplateTypeVariable {
		return nil, nil, nil
	}

	bases, entries := generateDiffEntriesFromVariantSet(response.VariablePacketTemplate, count)
	return bases, entries, nil
}

// GenerateRawEntries generates packet entries from raw packets
// Raw packets become base packets with diff_count=0, enabling memory deduplication
func GenerateRawEntries(packets []guest.BasePacket, count int) ([]BasePacketInfo, []DiffEntry) {
	if len(packets) == 0 {
		return nil, nil
	}

	// Deduplicate base packets
	bases := []BasePacketInfo{}
	baseKeyToIdx := make(map[string]uint8)
	packetToBaseIdx := make([]uint8, len(packets))

	for i, pkt := range packets {
		key := basePacketKey(pkt)
		if idx, exists := baseKeyToIdx[key]; exists {
			// Reuse existing base
			packetToBaseIdx[i] = idx
		} else {
			// New unique base
			idx := uint8(len(bases))
			baseKeyToIdx[key] = idx
			packetToBaseIdx[i] = idx
			bases = append(bases, BasePacketInfo{
				Base:      pkt,
				Checksums: nil, // Raw packets have pre-computed checksums
			})
		}
	}

	// Create diff entries with diff_count=0 (no modifications needed)
	// Round-robin through raw packets to fill count entries
	entries := make([]DiffEntry, count)
	for i := 0; i < count; i++ {
		pktIdx := i % len(packets)
		baseIdx := packetToBaseIdx[pktIdx]
		entries[i] = DiffEntry{
			BaseIdx:    baseIdx,
			PacketLen:  packets[pktIdx].Length,
			LenChanged: false,
			Diffs:      nil, // No diffs for raw packets
		}
	}

	return bases, entries
}
