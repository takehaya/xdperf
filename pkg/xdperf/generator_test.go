package xdperf

import (
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
)

func TestGenerateSingleEntry(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}
	// Set some initial data
	basePacket.Data[34] = 0x04 // src port high byte (1024 = 0x0400)
	basePacket.Data[35] = 0x00 // src port low byte

	tests := []struct {
		name     string
		variant  guest.PacketVariant
		baseIdx  uint8
		checkFn  func(t *testing.T, entry DiffEntry)
	}{
		{
			name: "sequential single param",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   34, // UDP src port
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 1024, End: 1026},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			baseIdx: 0,
			checkFn: func(t *testing.T, entry DiffEntry) {
				if entry.BaseIdx != 0 {
					t.Errorf("BaseIdx = %d, want 0", entry.BaseIdx)
				}
				if len(entry.Diffs) != 1 {
					t.Errorf("len(Diffs) = %d, want 1", len(entry.Diffs))
					return
				}
				if entry.Diffs[0].Offset != 34 {
					t.Errorf("Diffs[0].Offset = %d, want 34", entry.Diffs[0].Offset)
				}
				if entry.Diffs[0].Size != 2 {
					t.Errorf("Diffs[0].Size = %d, want 2", entry.Diffs[0].Size)
				}
				expected, _ := valueToBytes(1024, 2)
				if entry.Diffs[0].NewValue != expected {
					t.Errorf("Diffs[0].NewValue = %v, want %v", entry.Diffs[0].NewValue, expected)
				}
			},
		},
		{
			name: "packet length variation",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   guest.ByteStartPacketLength,
						ByteSize:    0,
						ByteRange:   guest.TemplateRange{Start: 64, End: 84},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			baseIdx: 1,
			checkFn: func(t *testing.T, entry DiffEntry) {
				if entry.BaseIdx != 1 {
					t.Errorf("BaseIdx = %d, want 1", entry.BaseIdx)
				}
				if entry.PacketLen != 64 {
					t.Errorf("PacketLen = %d, want 64", entry.PacketLen)
				}
				if !entry.LenChanged {
					t.Errorf("LenChanged = false, want true")
				}
				if len(entry.Diffs) != 0 {
					t.Errorf("len(Diffs) = %d, want 0 (packet length is not a diff)", len(entry.Diffs))
				}
			},
		},
		{
			name: "no params",
			variant: guest.PacketVariant{
				Base:   basePacket,
				Params: []guest.VariableParams{},
			},
			baseIdx: 2,
			checkFn: func(t *testing.T, entry DiffEntry) {
				if entry.BaseIdx != 2 {
					t.Errorf("BaseIdx = %d, want 2", entry.BaseIdx)
				}
				if entry.PacketLen != 100 {
					t.Errorf("PacketLen = %d, want 100", entry.PacketLen)
				}
				if entry.LenChanged {
					t.Errorf("LenChanged = true, want false")
				}
				if len(entry.Diffs) != 0 {
					t.Errorf("len(Diffs) = %d, want 0", len(entry.Diffs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newVariantState(tt.variant.Params)
			entry, err := generateSingleEntry(tt.variant, state, tt.baseIdx)
			if err != nil {
				t.Fatalf("generateSingleEntry failed: %v", err)
			}
			tt.checkFn(t, entry)
		})
	}
}

func TestGenerateDiffEntriesFromVariantSet_Sequential(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	variantSet := guest.PacketVariantSet{
		Pattern: guest.VariantSelectionModeSequential,
		Variants: []guest.PacketVariant{
			{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   34,
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 1000, End: 1002},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
				Weight: 3, // 75%
			},
			{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   34,
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 2000, End: 2002},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
				Weight: 1, // 25%
			},
		},
	}

	bases, entries, err := generateDiffEntriesFromVariantSet(variantSet, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 bases (one per variant, no deduplication)
	if len(bases) != 2 {
		t.Errorf("len(bases) = %d, want 2", len(bases))
	}

	// Should have 100 entries total
	if len(entries) != 100 {
		t.Errorf("len(entries) = %d, want 100", len(entries))
	}

	// Count entries per base
	countBase0 := 0
	countBase1 := 0
	for _, e := range entries {
		if e.BaseIdx == 0 {
			countBase0++
		} else if e.BaseIdx == 1 {
			countBase1++
		}
	}

	// In Sequential mode, first 75 entries should be base 0, last 25 should be base 1
	if countBase0 != 75 {
		t.Errorf("countBase0 = %d, want 75", countBase0)
	}
	if countBase1 != 25 {
		t.Errorf("countBase1 = %d, want 25", countBase1)
	}

	// Check that sequential values cycle correctly for first variant
	// Should cycle: 1000, 1001, 1002, 1000, 1001, ...
	for i := 0; i < 75; i++ {
		expectedVal := uint64(1000 + (i % 3))
		expected, _ := valueToBytes(expectedVal, 2)
		if entries[i].Diffs[0].NewValue != expected {
			t.Errorf("entries[%d].Diffs[0].NewValue = %v, want %v", i, entries[i].Diffs[0].NewValue, expected)
		}
	}
}

func TestGenerateRawEntries(t *testing.T) {
	packets := []guest.BasePacket{
		{Data: make([]byte, 64), Length: 64},
		{Data: make([]byte, 128), Length: 128},
		{Data: make([]byte, 256), Length: 256},
	}

	bases, entries, err := GenerateRawEntries(packets, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 3 bases (one per packet)
	if len(bases) != 3 {
		t.Errorf("len(bases) = %d, want 3", len(bases))
	}

	// Should have 10 entries
	if len(entries) != 10 {
		t.Errorf("len(entries) = %d, want 10", len(entries))
	}

	// Entries should round-robin through packets
	for i, e := range entries {
		expectedBaseIdx := uint8(i % 3)
		if e.BaseIdx != expectedBaseIdx {
			t.Errorf("entries[%d].BaseIdx = %d, want %d", i, e.BaseIdx, expectedBaseIdx)
		}
		if len(e.Diffs) != 0 {
			t.Errorf("entries[%d].Diffs should be empty for raw packets", i)
		}
		if e.LenChanged {
			t.Errorf("entries[%d].LenChanged should be false for raw packets", i)
		}
	}

	// Check packet lengths match
	expectedLengths := []uint16{64, 128, 256, 64, 128, 256, 64, 128, 256, 64}
	for i, e := range entries {
		if e.PacketLen != expectedLengths[i] {
			t.Errorf("entries[%d].PacketLen = %d, want %d", i, e.PacketLen, expectedLengths[i])
		}
	}
}

func TestGenerateRawEntries_Empty(t *testing.T) {
	bases, entries, err := GenerateRawEntries([]guest.BasePacket{}, 100)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if bases != nil {
		t.Errorf("bases should be nil for empty input")
	}
	if entries != nil {
		t.Errorf("entries should be nil for empty input")
	}
}

func TestGenerateVariableEntries(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	response := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeVariable,
		VariablePacketTemplate: guest.PacketVariantSet{
			Pattern: guest.VariantSelectionModeSequential,
			Variants: []guest.PacketVariant{
				{
					Base:   basePacket,
					Params: []guest.VariableParams{},
					Weight: 1,
				},
			},
		},
	}

	bases, entries, err := GenerateVariableEntries(response, 50)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(bases) != 1 {
		t.Errorf("len(bases) = %d, want 1", len(bases))
	}
	if len(entries) != 50 {
		t.Errorf("len(entries) = %d, want 50", len(entries))
	}
}

func TestGenerateVariableEntries_WrongType(t *testing.T) {
	response := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeRaw,
	}

	bases, entries, err := GenerateVariableEntries(response, 50)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if bases != nil || entries != nil {
		t.Errorf("should return nil for non-variable template type")
	}
}
