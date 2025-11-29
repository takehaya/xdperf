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

// makeTestUDPPacket creates a minimal valid UDP packet for testing.
// Ethernet (14) + IPv4 (20) + UDP (8) + payload = 42+ bytes
func makeTestUDPPacket(payloadSize int) []byte {
	pkt := make([]byte, 42+payloadSize)
	// Ethernet header (14 bytes)
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})   // dst MAC
	copy(pkt[6:12], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})  // src MAC
	pkt[12], pkt[13] = 0x08, 0x00                                 // EtherType: IPv4
	// IPv4 header (20 bytes) at offset 14
	pkt[14] = 0x45                                                // Version + IHL
	pkt[15] = 0x00                                                // DSCP + ECN
	totalLen := uint16(20 + 8 + payloadSize)
	pkt[16], pkt[17] = byte(totalLen>>8), byte(totalLen)          // Total length
	pkt[18], pkt[19] = 0x00, 0x00                                 // Identification
	pkt[20], pkt[21] = 0x00, 0x00                                 // Flags + Fragment offset
	pkt[22] = 0x40                                                // TTL
	pkt[23] = 0x11                                                // Protocol: UDP
	pkt[24], pkt[25] = 0x00, 0x00                                 // Header checksum (will be calculated)
	copy(pkt[26:30], []byte{192, 168, 1, 1})                      // Src IP
	copy(pkt[30:34], []byte{10, 0, 0, 1})                         // Dst IP
	// UDP header (8 bytes) at offset 34
	pkt[34], pkt[35] = 0x04, 0xd2                                 // Src port: 1234
	pkt[36], pkt[37] = 0x16, 0x2e                                 // Dst port: 5678
	udpLen := uint16(8 + payloadSize)
	pkt[38], pkt[39] = byte(udpLen>>8), byte(udpLen)              // UDP length
	pkt[40], pkt[41] = 0x00, 0x00                                 // UDP checksum
	return pkt
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
					Data:   makeTestUDPPacket(10),
					Length: 52,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   42, // first payload byte
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
					if e.Data[42] != expectedVals[i] {
						t.Errorf("entry[%d]: byte[42] = %d, want %d", i, e.Data[42], expectedVals[i])
					}
				}
			},
		},
		{
			name: "two byte sequential (network byte order)",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   makeTestUDPPacket(10),
					Length: 52,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   34, // UDP src port
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
					if e.Data[34] != expected[i][0] || e.Data[35] != expected[i][1] {
						t.Errorf("entry[%d]: bytes[34:36] = [%02x, %02x], want [%02x, %02x]",
							i, e.Data[34], e.Data[35], expected[i][0], expected[i][1])
					}
				}
			},
		},
		{
			name: "multiple params",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   makeTestUDPPacket(10),
					Length: 52,
				},
				Params: []guest.VariableParams{
					{
						ByteStart:   42, // payload byte 0
						ByteSize:    1,
						ByteRange:   guest.TemplateRange{Start: 1, End: 2},
						PatternType: guest.ValuePatternTypeSequential,
					},
					{
						ByteStart:   43, // payload byte 1
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
					if e.Data[42] != expected[i][0] || e.Data[43] != expected[i][1] {
						t.Errorf("entry[%d]: bytes[42:44] = [%d, %d], want [%d, %d]",
							i, e.Data[42], e.Data[43], expected[i][0], expected[i][1])
					}
				}
			},
		},
		{
			name: "zero count",
			variant: guest.PacketVariant{
				Base: guest.BasePacket{
					Data:   makeTestUDPPacket(0),
					Length: 42,
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
					Data:   makeTestUDPPacket(0),
					Length: 42,
				},
				Params: []guest.VariableParams{
					{
						ByteStart: 100, // out of bounds
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
		value    uint64
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
			name:     "4 byte value big endian",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			param:    guest.VariableParams{ByteStart: 1, ByteSize: 4},
			value:    0x12345678,
			expected: []byte{0x00, 0x12, 0x34, 0x56, 0x78, 0x00},
		},
		{
			name:     "8 byte value big endian",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			param:    guest.VariableParams{ByteStart: 1, ByteSize: 8},
			value:    0x123456789ABCDEF0,
			expected: []byte{0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00},
		},
		{
			name:    "unsupported byte size",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			param:   guest.VariableParams{ByteStart: 0, ByteSize: 3},
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
