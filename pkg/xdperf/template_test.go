package xdperf

import (
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
)

func TestCalculateVariantCounts(t *testing.T) {
	tests := []struct {
		name       string
		variants   []guest.PacketVariant
		totalCount uint64
		expected   []uint64
	}{
		{
			name: "single variant",
			variants: []guest.PacketVariant{
				{Weight: 1},
			},
			totalCount: 100,
			expected:   []uint64{100},
		},
		{
			name: "two variants equal weight",
			variants: []guest.PacketVariant{
				{Weight: 1},
				{Weight: 1},
			},
			totalCount: 100,
			expected:   []uint64{50, 50},
		},
		{
			name: "two variants 3:1 weight",
			variants: []guest.PacketVariant{
				{Weight: 3},
				{Weight: 1},
			},
			totalCount: 100,
			expected:   []uint64{75, 25},
		},
		{
			name: "three variants with remainder",
			variants: []guest.PacketVariant{
				{Weight: 1},
				{Weight: 1},
				{Weight: 1},
			},
			totalCount: 100,
			expected:   []uint64{34, 33, 33},
		},
		{
			name: "zero weights - distribute evenly",
			variants: []guest.PacketVariant{
				{Weight: 0},
				{Weight: 0},
			},
			totalCount: 100,
			expected:   []uint64{50, 50},
		},
		{
			name:       "empty variants",
			variants:   []guest.PacketVariant{},
			totalCount: 100,
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateVariantCounts(tt.variants, tt.totalCount)

			if len(result) != len(tt.expected) {
				t.Errorf("length mismatch: got %d, want %d", len(result), len(tt.expected))
				return
			}

			var total uint64
			for i, v := range result {
				total += v
				if v != tt.expected[i] {
					t.Errorf("count[%d]: got %d, want %d", i, v, tt.expected[i])
				}
			}

			if len(result) > 0 && total != tt.totalCount {
				t.Errorf("total count mismatch: got %d, want %d", total, tt.totalCount)
			}
		})
	}
}

func TestExpandVariant(t *testing.T) {
	tests := []struct {
		name     string
		variant  guest.PacketVariant
		count    uint64
		checkFn  func(t *testing.T, entries []*TxOverrideEntry)
		wantErr  bool
	}{
		{
			name: "single byte sequential",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   []byte{0x00, 0x01, 0x02, 0x03, 0x04},
					Length: 5,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   2,
						ByteSize:    1,
						ByteRange:   guest.TemplateRange{Start: 10, End: 12},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			count: 5,
			checkFn: func(t *testing.T, entries []*TxOverrideEntry) {
				if len(entries) != 5 {
					t.Errorf("expected 5 entries, got %d", len(entries))
					return
				}
				// Values should cycle: 10, 11, 12, 10, 11
				expectedVals := []byte{10, 11, 12, 10, 11}
				for i, e := range entries {
					if e.Data[2] != expectedVals[i] {
						t.Errorf("entry[%d]: byte[2] = %d, want %d", i, e.Data[2], expectedVals[i])
					}
				}
			},
		},
		{
			name: "two byte sequential (network byte order)",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
					Length: 6,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   2,
						ByteSize:    2,
						ByteRange:   guest.TemplateRange{Start: 256, End: 258},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			count: 3,
			checkFn: func(t *testing.T, entries []*TxOverrideEntry) {
				if len(entries) != 3 {
					t.Errorf("expected 3 entries, got %d", len(entries))
					return
				}
				// 256 = 0x0100, 257 = 0x0101, 258 = 0x0102 in big endian
				expected := [][]byte{
					{0x01, 0x00}, // 256
					{0x01, 0x01}, // 257
					{0x01, 0x02}, // 258
				}
				for i, e := range entries {
					if e.Data[2] != expected[i][0] || e.Data[3] != expected[i][1] {
						t.Errorf("entry[%d]: bytes[2:4] = [%02x, %02x], want [%02x, %02x]",
							i, e.Data[2], e.Data[3], expected[i][0], expected[i][1])
					}
				}
			},
		},
		{
			name: "multiple params",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   []byte{0x00, 0x00, 0x00, 0x00},
					Length: 4,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   0,
						ByteSize:    1,
						ByteRange:   guest.TemplateRange{Start: 1, End: 2},
						PatternType: guest.ValuePatternTypeSequential,
					},
					{
						ByteStart:   1,
						ByteSize:    1,
						ByteRange:   guest.TemplateRange{Start: 10, End: 11},
						PatternType: guest.ValuePatternTypeSequential,
					},
				},
			},
			count: 4,
			checkFn: func(t *testing.T, entries []*TxOverrideEntry) {
				if len(entries) != 4 {
					t.Errorf("expected 4 entries, got %d", len(entries))
					return
				}
				// Both params increment together
				// [1,10], [2,11], [1,10], [2,11]
				expected := [][]byte{
					{1, 10},
					{2, 11},
					{1, 10},
					{2, 11},
				}
				for i, e := range entries {
					if e.Data[0] != expected[i][0] || e.Data[1] != expected[i][1] {
						t.Errorf("entry[%d]: bytes[0:2] = [%d, %d], want [%d, %d]",
							i, e.Data[0], e.Data[1], expected[i][0], expected[i][1])
					}
				}
			},
		},
		{
			name: "zero count",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   []byte{0x00},
					Length: 1,
				},
			},
			count: 0,
			checkFn: func(t *testing.T, entries []*TxOverrideEntry) {
				if len(entries) != 0 {
					t.Errorf("expected 0 entries, got %d", len(entries))
				}
			},
		},
		{
			name: "byte range out of bounds",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   []byte{0x00, 0x01},
					Length: 2,
				},
				Params: []guest.VariableParams{
					{
						ByteStart: 10, // out of bounds
						ByteSize:  1,
						ByteRange: guest.TemplateRange{Start: 0, End: 1},
					},
				},
			},
			count:   1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := expandVariant(tt.variant, tt.count)

			if (err != nil) != tt.wantErr {
				t.Errorf("expandVariant() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkFn != nil && !tt.wantErr {
				tt.checkFn(t, entries)
			}
		})
	}
}

func TestApplyVariableParam(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		param    guest.VariableParams
		value    uint16
		expected []byte
		wantErr  bool
	}{
		{
			name:     "1 byte value",
			data:     []byte{0x00, 0x00, 0x00},
			param:    guest.VariableParams{ByteStart: 1, ByteSize: 1},
			value:    42,
			expected: []byte{0x00, 42, 0x00},
		},
		{
			name:     "2 byte value big endian",
			data:     []byte{0x00, 0x00, 0x00, 0x00},
			param:    guest.VariableParams{ByteStart: 1, ByteSize: 2},
			value:    0x1234,
			expected: []byte{0x00, 0x12, 0x34, 0x00},
		},
		{
			name:    "unsupported byte size",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			param:   guest.VariableParams{ByteStart: 0, ByteSize: 4},
			value:   0,
			wantErr: true,
		},
		{
			name:    "out of bounds",
			data:    []byte{0x00},
			param:   guest.VariableParams{ByteStart: 0, ByteSize: 2},
			value:   0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, len(tt.data))
			copy(data, tt.data)

			err := applyVariableParam(data, tt.param, tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("applyVariableParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				for i, b := range data {
					if b != tt.expected[i] {
						t.Errorf("data[%d] = %02x, want %02x", i, b, tt.expected[i])
					}
				}
			}
		})
	}
}
