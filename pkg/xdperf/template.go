package xdperf

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
// Each param can be sequential or mixed based on its PatternType.
// If a param has ByteStart == ByteStartPacketLength, it controls packet length.
func expandVariant(variant guest.PacketVariant, count uint64) ([]*TxOverrideEntry, error) {
	if count == 0 {
		return nil, nil
	}

	// Initialize state for sequential params
	currentValues := make([]uint16, len(variant.Params))
	for i, p := range variant.Params {
		currentValues[i] = p.ByteRange.Start
	}

	entries := make([]*TxOverrideEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		entry, err := expandSinglePacket(variant, currentValues)
		if err != nil {
			return nil, fmt.Errorf("failed to expand packet %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// updatePacketLength updates packet headers (IP, transport) for a new packet length.
// Uses gopacket to support any protocol stack.
func updatePacketLength(data []byte, newLen uint16) ([]byte, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Get network layer for checksum calculation
	networkLayer := packet.NetworkLayer()

	// Collect all serializable layers except payload
	var serializableLayers []gopacket.SerializableLayer
	for _, layer := range packet.Layers() {
		if layer.LayerType() == gopacket.LayerTypePayload {
			break
		}
		sl, ok := layer.(gopacket.SerializableLayer)
		if !ok {
			continue
		}
		// Set network layer for transport checksum calculation
		switch l := layer.(type) {
		case *layers.UDP:
			if networkLayer != nil {
				_ = l.SetNetworkLayerForChecksum(networkLayer)
			}
		case *layers.TCP:
			if networkLayer != nil {
				_ = l.SetNetworkLayerForChecksum(networkLayer)
			}
		}
		serializableLayers = append(serializableLayers, sl)
	}

	// Adjust payload to new length
	headerLen := calculateHeaderLength(packet)
	payloadLen := int(newLen) - headerLen
	if payloadLen < 0 {
		payloadLen = 0
	}
	payload := make([]byte, payloadLen)
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		copy(payload, appLayer.Payload())
	}
	serializableLayers = append(serializableLayers, gopacket.Payload(payload))

	// Serialize with automatic length and checksum calculation
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, serializableLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return buf.Bytes(), nil
}

// calculateHeaderLength calculates the total header length of a packet
// by summing all layer contents except the payload.
func calculateHeaderLength(packet gopacket.Packet) int {
	length := 0
	for _, layer := range packet.Layers() {
		if layer.LayerType() == gopacket.LayerTypePayload {
			break
		}
		length += len(layer.LayerContents())
	}
	return length
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
// It generates totalCount packets total, using the Pattern to determine variant selection.
// These packets will be distributed across CPUs by initTxOverrideMap.
func (x *Xdperf) convVariableTemplate(variantSet guest.PacketVariantSet, totalCount uint64, parallelism int) ([]*TxOverrideEntry, error) {
	if len(variantSet.Variants) == 0 {
		return nil, fmt.Errorf("no variants in packet variant set")
	}

	var allEntries []*TxOverrideEntry
	var err error

	switch variantSet.Pattern {
	case guest.VariantSelectionModeSequential:
		allEntries, err = x.convVariableTemplateSequential(variantSet, totalCount)
	case guest.VariantSelectionModeMixed:
		allEntries, err = x.convVariableTemplateMixed(variantSet, totalCount)
	default:
		return nil, fmt.Errorf("unsupported variant selection pattern: %q", variantSet.Pattern)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s template: %w", variantSet.Pattern, err)
	}

	x.Logger.Info("generated variable template packets",
		zap.Int("total_entries", len(allEntries)),
		zap.Uint64("total_count", totalCount),
		zap.Int("parallelism", parallelism),
		zap.String("pattern", string(variantSet.Pattern)),
	)

	return allEntries, nil
}

// convVariableTemplateSequential generates packets by expanding each variant fully
// before moving to the next one. Weight determines how many packets each variant gets.
func (x *Xdperf) convVariableTemplateSequential(variantSet guest.PacketVariantSet, totalCount uint64) ([]*TxOverrideEntry, error) {
	// Calculate packet count for each variant based on weight
	variantCounts := calculateVariantCounts(variantSet.Variants, totalCount)

	// Expand each variant sequentially
	var allEntries []*TxOverrideEntry
	for i, variant := range variantSet.Variants {
		entries, err := expandVariant(variant, variantCounts[i])
		if err != nil {
			return nil, fmt.Errorf("failed to expand variant %d: %w", i, err)
		}
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

// convVariableTemplateMixed generates packets by selecting a variant for each packet using weighted randomization.
// Selection is weighted by the variant's Weight field.
func (x *Xdperf) convVariableTemplateMixed(variantSet guest.PacketVariantSet, totalCount uint64) ([]*TxOverrideEntry, error) {
	variants := variantSet.Variants

	// Calculate total weight
	var totalWeight uint64
	for _, v := range variants {
		totalWeight += uint64(v.Weight)
	}
	// If all weights are zero, treat as equal weight
	if totalWeight == 0 {
		totalWeight = uint64(len(variants))
	}

	// Track current values for each variant's params (for sequential VariableParams)
	variantStates := make([][]uint16, len(variants))
	for i, v := range variants {
		variantStates[i] = make([]uint16, len(v.Params))
		for j, p := range v.Params {
			variantStates[i][j] = p.ByteRange.Start
		}
	}

	entries := make([]*TxOverrideEntry, 0, totalCount)
	for i := uint64(0); i < totalCount; i++ {
		// Select variant by weight
		variantIdx := selectVariantByWeight(variants, totalWeight)

		// Generate one packet from the selected variant
		entry, err := expandSinglePacket(variants[variantIdx], variantStates[variantIdx])
		if err != nil {
			return nil, fmt.Errorf("failed to expand packet %d from variant %d: %w", i, variantIdx, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// selectVariantByWeight selects a variant index based on weighted selection.
func selectVariantByWeight(variants []guest.PacketVariant, totalWeight uint64) int {
	if len(variants) == 1 {
		return 0
	}

	r := rand.Uint64() % totalWeight
	var cumulative uint64
	for i, v := range variants {
		weight := uint64(v.Weight)
		if weight == 0 {
			weight = 1 // treat zero weight as 1 for equal distribution
		}
		cumulative += weight
		if r < cumulative {
			return i
		}
	}
	return len(variants) - 1
}

// expandSinglePacket generates a single packet from a variant, updating the state for sequential params.
func expandSinglePacket(variant guest.PacketVariant, currentValues []uint16) (*TxOverrideEntry, error) {
	baseData := variant.Base.Data
	baseLen := variant.Base.Length
	params := variant.Params

	// Copy base packet
	data := make([]byte, len(baseData))
	copy(data, baseData)

	// Default packet length
	packetLen := baseLen

	// Apply each variable param
	for j, p := range params {
		var value uint16
		switch p.PatternType {
		case guest.ValuePatternTypeMixed:
			rangeSize := int(p.ByteRange.End-p.ByteRange.Start) + 1
			value = p.ByteRange.Start + uint16(rand.Intn(rangeSize))
		default:
			// Sequential
			value = currentValues[j]
			currentValues[j]++
			if currentValues[j] > p.ByteRange.End {
				currentValues[j] = p.ByteRange.Start
			}
		}

		if p.ByteStart == guest.ByteStartPacketLength {
			packetLen = value
		} else if err := applyVariableParam(data, p, value); err != nil {
			return nil, fmt.Errorf("failed to apply variable param %d: %w", j, err)
		}
	}

	// If packet length changed, update headers using gopacket
	if packetLen != baseLen {
		var err error
		data, err = updatePacketLength(data, packetLen)
		if err != nil {
			return nil, fmt.Errorf("failed to update packet length: %w", err)
		}
	}

	return &TxOverrideEntry{
		Data:   data,
		Length: packetLen,
	}, nil
}
