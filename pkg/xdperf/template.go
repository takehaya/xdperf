package xdperf

import (
	"encoding/binary"
	"fmt"

	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// calculateVariantCounts calculates the number of packets to generate for each variant
// based on their weights and the total count.
// The total of all returned counts equals totalCount.
func calculateVariantCounts(variants []guest.PacketVariant, totalCount uint64) []uint64 {
	if len(variants) == 0 {
		return nil
	}

	// Calculate total weight
	var totalWeight uint64
	for _, v := range variants {
		totalWeight += uint64(v.Weight)
	}

	// If all weights are zero, distribute evenly
	if totalWeight == 0 {
		countPerVariant := totalCount / uint64(len(variants))
		remainder := totalCount % uint64(len(variants))
		counts := make([]uint64, len(variants))
		for i := range counts {
			counts[i] = countPerVariant
			if uint64(i) < remainder {
				counts[i]++
			}
		}
		return counts
	}

	// Distribute based on weight
	counts := make([]uint64, len(variants))
	var allocated uint64
	for i, v := range variants {
		counts[i] = (uint64(v.Weight) * totalCount) / totalWeight
		allocated += counts[i]
	}

	// Distribute remainder to variants with highest weight
	remainder := totalCount - allocated
	for i := 0; remainder > 0; i = (i + 1) % len(variants) {
		counts[i]++
		remainder--
	}

	return counts
}

// expandVariant generates multiple packets from a single variant by applying variable params.
// All VariableParams are incremented simultaneously.
// If LengthRange is set, packet length also varies within that range.
func expandVariant(variant guest.PacketVariant, count uint64) ([]*TxOverrideEntry, error) {
	if count == 0 {
		return nil, nil
	}

	baseData := variant.Base.Data
	baseLen := variant.Base.Length
	params := variant.Params
	lengthRange := variant.LengthRange

	entries := make([]*TxOverrideEntry, 0, count)

	// Track current value for each param
	currentValues := make([]uint16, len(params))
	for i, p := range params {
		currentValues[i] = p.ByteRange.Start
	}

	// Track current length if length range is set
	var currentLength uint16
	if lengthRange != nil {
		currentLength = lengthRange.Start
	} else {
		currentLength = baseLen
	}

	for i := uint64(0); i < count; i++ {
		// Copy base packet
		data := make([]byte, len(baseData))
		copy(data, baseData)

		// Apply each variable param
		for j, p := range params {
			if err := applyVariableParam(data, p, currentValues[j]); err != nil {
				return nil, fmt.Errorf("failed to apply variable param %d: %w", j, err)
			}

			// Increment value for next iteration
			currentValues[j]++
			if currentValues[j] > p.ByteRange.End {
				currentValues[j] = p.ByteRange.Start
			}
		}

		// Determine packet length for this entry
		packetLen := currentLength

		// Increment length for next iteration if length range is set
		if lengthRange != nil {
			currentLength++
			if currentLength > lengthRange.End {
				currentLength = lengthRange.Start
			}
		}

		entries = append(entries, &TxOverrideEntry{
			Data:   data,
			Length: packetLen,
		})
	}

	return entries, nil
}

// applyVariableParam applies a single variable param to packet data.
// The value is written in network byte order (big endian).
func applyVariableParam(data []byte, param guest.VariableParams, value uint16) error {
	start := param.ByteStart
	size := param.ByteSize

	if start+size > uint64(len(data)) {
		return fmt.Errorf("byte range [%d:%d] exceeds packet length %d", start, start+size, len(data))
	}

	switch size {
	case 1:
		data[start] = byte(value)
	case 2:
		binary.BigEndian.PutUint16(data[start:start+2], value)
	default:
		return fmt.Errorf("unsupported byte size: %d (only 1 or 2 supported)", size)
	}

	return nil
}

// convVariableTemplate converts a PacketVariantSet to TxOverrideEntries.
// It generates totalCount packets total, distributed by weight.
// These packets will be distributed across CPUs by initTxOverrideMap.
func (x *Xdperf) convVariableTemplate(variantSet guest.PacketVariantSet, totalCount uint64, parallelism int) ([]*TxOverrideEntry, error) {
	if len(variantSet.Variants) == 0 {
		return nil, fmt.Errorf("no variants in packet variant set")
	}

	// Generate all packets (totalCount)
	variantCounts := calculateVariantCounts(variantSet.Variants, totalCount)

	var allEntries []*TxOverrideEntry
	for i, variant := range variantSet.Variants {
		entries, err := expandVariant(variant, variantCounts[i])
		if err != nil {
			return nil, fmt.Errorf("failed to expand variant %d: %w", i, err)
		}
		allEntries = append(allEntries, entries...)
	}

	x.Logger.Info("generated variable template packets",
		zap.Int("total_entries", len(allEntries)),
		zap.Uint64("total_count", totalCount),
		zap.Int("parallelism", parallelism),
	)

	return allEntries, nil
}
