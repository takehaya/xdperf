package xdperf

import (
	"math/rand"
	"strings"
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

func TestGenerateSingleEntry_Errors(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	tests := []struct {
		name    string
		variant guest.PacketVariant
		wantErr string
	}{
		{
			name: "ByteStart exceeds MaxUint16",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   1 << 17, // Exceeds math.MaxUint16
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 1000, End: 1002},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			wantErr: "byte_start",
		},
		{
			name: "ByteSize exceeds 8",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   34,
						ByteSize:    9, // Exceeds max 8
						ByteRange:   guest.TemplateRange{Start: 1000, End: 1002},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			wantErr: "byte_size",
		},
		{
			name: "readBytesAt failure - offset out of range",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   99, // offset 99 + size 4 = 103 > 100
						ByteSize:    4,
						ByteRange:   guest.TemplateRange{Start: 1000, End: 1002},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			wantErr: "failed to read bytes",
		},
		{
			name: "ByteRange Start > End for sequential pattern",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   34,
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 2000, End: 1000}, // Invalid: Start > End
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			wantErr: "invalid range",
		},
		{
			name: "ByteRange Start > End for packet length sequential",
			variant: guest.PacketVariant{
				Base: basePacket,
				Params: []guest.VariableParams{
					{
						ByteStart:   guest.ByteStartPacketLength,
						ByteSize:    0,
						ByteRange:   guest.TemplateRange{Start: 200, End: 100}, // Invalid: Start > End
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			wantErr: "invalid range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newVariantState(tt.variant.Params)
			_, err := generateSingleEntry(tt.variant, state, 0)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want error containing %q", err.Error(), tt.wantErr)
			}
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

	bases, entries, err := generateDiffEntriesFromVariantSet(variantSet, 100, 16)
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

func TestGenerateDiffEntriesFromVariantSet_Default(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	// Use empty Pattern (unknown) to test default behavior
	variantSet := guest.PacketVariantSet{
		Pattern: guest.VariantSelectionModeUnknown, // Default/empty pattern
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
				Weight: 1,
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
				Weight: 1,
			},
		},
	}

	bases, entries, err := generateDiffEntriesFromVariantSet(variantSet, 10, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 bases (even though only first is used)
	if len(bases) != 2 {
		t.Errorf("len(bases) = %d, want 2", len(bases))
	}

	// Should have 10 entries
	if len(entries) != 10 {
		t.Errorf("len(entries) = %d, want 10", len(entries))
	}

	// In default mode, only first variant (baseIdx=0) should be used
	for i, e := range entries {
		if e.BaseIdx != 0 {
			t.Errorf("entries[%d].BaseIdx = %d, want 0 (default mode uses first variant only)", i, e.BaseIdx)
		}
	}

	// Check sequential values cycle correctly: 1000, 1001, 1002, 1000, ...
	for i := 0; i < 10; i++ {
		expectedVal := uint64(1000 + (i % 3))
		expected, _ := valueToBytes(expectedVal, 2)
		if entries[i].Diffs[0].NewValue != expected {
			t.Errorf("entries[%d].Diffs[0].NewValue = %v, want %v", i, entries[i].Diffs[0].NewValue, expected)
		}
	}
}

func TestGenerateDiffEntriesFromVariantSet_Mixed(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	variantSet := guest.PacketVariantSet{
		Pattern: guest.VariantSelectionModeMixed,
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
				Weight: 1,
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
				Weight: 1,
			},
		},
	}

	// Use fixed seed for reproducible test
	rng := rand.New(rand.NewSource(12345))
	bases, entries, err := generateDiffEntriesFromVariantSetWith(rng, variantSet, 100, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 bases
	if len(bases) != 2 {
		t.Errorf("len(bases) = %d, want 2", len(bases))
	}

	// Should have 100 entries
	if len(entries) != 100 {
		t.Errorf("len(entries) = %d, want 100", len(entries))
	}

	// In Mixed mode, both variants should be selected (random, but with equal weight)
	countBase0 := 0
	countBase1 := 0
	for _, e := range entries {
		if e.BaseIdx == 0 {
			countBase0++
		} else if e.BaseIdx == 1 {
			countBase1++
		}
	}

	// With equal weights and 100 entries, both should be selected at least once
	if countBase0 == 0 {
		t.Errorf("variant 0 was never selected in mixed mode")
	}
	if countBase1 == 0 {
		t.Errorf("variant 1 was never selected in mixed mode")
	}

	// Total should be 100
	if countBase0+countBase1 != 100 {
		t.Errorf("total entries = %d, want 100", countBase0+countBase1)
	}
}

func TestGenerateRawEntries(t *testing.T) {
	packets := []guest.BasePacket{
		{Data: make([]byte, 64), Length: 64},
		{Data: make([]byte, 128), Length: 128},
		{Data: make([]byte, 256), Length: 256},
	}

	bases, entries, err := GenerateRawEntries(packets, 10, 16)
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
	bases, entries, err := GenerateRawEntries([]guest.BasePacket{}, 100, 16)

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

	bases, entries, err := GenerateVariableEntries(response, 50, 16)

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

func TestGenerateDiffEntriesFromVariantSet_TooManyVariants(t *testing.T) {
	basePacket := guest.BasePacket{
		Data:   make([]byte, 100),
		Length: 100,
	}

	// Create 17 variants (exceeds maxBasePackets = 16)
	variants := make([]guest.PacketVariant, 17)
	for i := range variants {
		variants[i] = guest.PacketVariant{
			Base:   basePacket,
			Params: []guest.VariableParams{},
			Weight: 1,
		}
	}

	variantSet := guest.PacketVariantSet{
		Pattern:  guest.VariantSelectionModeSequential,
		Variants: variants,
	}

	_, _, err := generateDiffEntriesFromVariantSet(variantSet, 100, 16)
	if err == nil {
		t.Fatal("expected error for too many variants, got nil")
	}
	if !strings.Contains(err.Error(), "too many variants") {
		t.Errorf("error = %q, want error containing 'too many variants'", err.Error())
	}
}

func TestGenerateRawEntries_TooManyPackets(t *testing.T) {
	// Create 17 packets (exceeds maxBasePackets = 16)
	packets := make([]guest.BasePacket, 17)
	for i := range packets {
		packets[i] = guest.BasePacket{
			Data:   make([]byte, 100),
			Length: 100,
		}
	}

	_, _, err := GenerateRawEntries(packets, 100, 16)
	if err == nil {
		t.Fatal("expected error for too many raw packets, got nil")
	}
	if !strings.Contains(err.Error(), "too many raw packets") {
		t.Errorf("error = %q, want error containing 'too many raw packets'", err.Error())
	}
}

func TestGenerateVariableEntries_WrongType(t *testing.T) {
	response := guest.GeneratorProcessResponse{
		TemplateType: guest.GeneratorTemplateTypeRaw,
	}

	bases, entries, err := GenerateVariableEntries(response, 50, 16)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if bases != nil || entries != nil {
		t.Errorf("should return nil for non-variable template type")
	}
}
