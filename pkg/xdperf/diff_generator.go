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

// generateDiffEntries generates diff entries from VariableParams
// This pre-computes all the diff values that will be applied in eBPF
func generateDiffEntries(base guest.BasePacket, params []guest.VariableParams, checksums []guest.ChecksumSpec, count int) []DiffEntry {
	entries := make([]DiffEntry, count)

	// Track current values for sequential patterns
	currentValues := make([]uint64, len(params))
	for i, p := range params {
		currentValues[i] = p.ByteRange.Start
	}

	for i := 0; i < count; i++ {
		entry := DiffEntry{
			PacketLen: base.Length,
			Diffs:     make([]DiffValue, 0, len(params)),
		}

		for j, p := range params {
			var value uint64

			switch p.PatternType {
			case guest.ValuePatternTypeSequential:
				value = currentValues[j]
				// Increment for next iteration
				currentValues[j]++
				if currentValues[j] > p.ByteRange.End {
					currentValues[j] = p.ByteRange.Start
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
				oldValue := readValueAt(base.Data, uint16(p.ByteStart), uint8(p.ByteSize))
				entry.Diffs = append(entry.Diffs, DiffValue{
					Offset:   uint16(p.ByteStart),
					Size:     uint8(p.ByteSize),
					OldValue: oldValue,
					NewValue: uint32(value),
				})
			}
		}

		// Check if packet length changed from base
		entry.LenChanged = entry.PacketLen != base.Length

		entries[i] = entry
	}

	return entries
}

// generateDiffEntriesFromVariant generates diff entries for a single variant
func generateDiffEntriesFromVariant(variant guest.PacketVariant, count int) []DiffEntry {
	return generateDiffEntries(variant.Base, variant.Params, variant.Checksums, count)
}

// generateDiffEntriesFromVariantSet generates diff entries from a variant set
// Handles both sequential and mixed selection modes
func generateDiffEntriesFromVariantSet(variantSet guest.PacketVariantSet, totalCount int) (guest.BasePacket, []DiffEntry, []guest.ChecksumSpec) {
	if len(variantSet.Variants) == 0 {
		return guest.BasePacket{}, nil, nil
	}

	// For differential mode, we use the first variant's base packet
	// All variants should have the same base structure
	base := variantSet.Variants[0].Base
	checksums := variantSet.Variants[0].Checksums

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
				entries := generateDiffEntriesFromVariant(v, variantCount)
				allEntries = append(allEntries, entries...)
			}
		}

	case guest.VariantSelectionModeMixed:
		// Calculate total weight for weighted random selection
		var totalWeight uint32
		for _, v := range variantSet.Variants {
			totalWeight += v.Weight
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

			// Generate single entry from selected variant
			entries := generateDiffEntriesFromVariant(variantSet.Variants[selectedIdx], 1)
			allEntries = append(allEntries, entries...)
		}

	default:
		// Default to first variant
		allEntries = generateDiffEntriesFromVariant(variantSet.Variants[0], totalCount)
	}

	return base, allEntries, checksums
}

// ConvertVariableTemplateToDifferential converts a variable template response
// to the differential format (base packet + diff entries)
func ConvertVariableTemplateToDifferential(response guest.GeneratorProcessResponse, count int) (guest.BasePacket, []DiffEntry, []guest.ChecksumSpec, error) {
	if response.TemplateType != guest.GeneratorTemplateTypeVariable {
		return guest.BasePacket{}, nil, nil, nil
	}

	base, entries, checksums := generateDiffEntriesFromVariantSet(response.VariablePacketTemplate, count)
	return base, entries, checksums, nil
}
