package xdperf

import "testing"

func TestParseCount(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		// Valid cases - empty
		{"empty string", "", 0, false},
		{"whitespace only", "   ", 0, false},

		// Valid cases - plain numbers
		{"plain number", "100", 100, false},
		{"large number", "1000000", 1000000, false},
		{"zero value", "0", 0, false},

		// Valid cases - k suffix
		{"k suffix lowercase", "100k", 100000, false},
		{"k suffix uppercase", "100K", 100000, false},
		{"k suffix with spaces", "  100k  ", 100000, false},
		{"1k", "1k", 1000, false},

		// Valid cases - m suffix
		{"m suffix lowercase", "1m", 1000000, false},
		{"m suffix uppercase", "1M", 1000000, false},
		{"m suffix larger", "10m", 10000000, false},

		// Error cases
		{"negative number", "-100", 0, true},
		{"invalid string", "abc", 0, true},
		{"float value", "2.5m", 0, true},
		{"invalid suffix", "100g", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCount(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCount(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseCount(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePPS(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		// Valid cases - empty (unlimited)
		{"empty string", "", 0, false},
		{"whitespace only", "   ", 0, false},

		// Valid cases - plain numbers
		{"plain number", "100", 100, false},
		{"large number", "1000000", 1000000, false},
		{"zero value", "0", 0, false},

		// Valid cases - k suffix
		{"k suffix lowercase", "100k", 100000, false},
		{"k suffix uppercase", "100K", 100000, false},
		{"k suffix with spaces", "  100k  ", 100000, false},

		// Valid cases - m suffix
		{"m suffix lowercase", "1m", 1000000, false},
		{"m suffix uppercase", "1M", 1000000, false},
		{"m suffix larger", "10m", 10000000, false},

		// Error cases
		{"negative number", "-100", 0, true},
		{"invalid string", "abc", 0, true},
		{"float value", "2.5m", 0, true},
		{"invalid suffix", "100g", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePPS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePPS(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParsePPS(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
