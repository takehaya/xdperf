package xdperf

import (
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
)

func TestValidateChecksumSpec(t *testing.T) {
	const dataLen = 64 // e.g. Eth(14) + IPv4(20) + UDP(8) + payload

	tests := []struct {
		name    string
		cs      guest.ChecksumSpec
		wantErr bool
	}{
		{
			name: "valid_udp_over_ipv4",
			cs:   guest.ChecksumSpec{IPHeaderOffset: 14, ChecksumOffset: 40, HeaderStart: 34, HeaderLen: 8},
		},
		{
			name: "valid_header_len_zero", // 0 = compute from IP/transport length
			cs:   guest.ChecksumSpec{IPHeaderOffset: 14, ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 0},
		},
		{
			name: "valid_checksum_at_end",
			cs:   guest.ChecksumSpec{IPHeaderOffset: 14, ChecksumOffset: 62, HeaderStart: 14, HeaderLen: 20},
		},
		{
			name:    "ip_header_offset_past_end",
			cs:      guest.ChecksumSpec{IPHeaderOffset: 64, ChecksumOffset: 40, HeaderStart: 34, HeaderLen: 8},
			wantErr: true,
		},
		{
			name:    "checksum_offset_overruns_by_one",
			cs:      guest.ChecksumSpec{IPHeaderOffset: 14, ChecksumOffset: 63, HeaderStart: 34, HeaderLen: 8},
			wantErr: true,
		},
		{
			name:    "header_start_plus_len_past_end",
			cs:      guest.ChecksumSpec{IPHeaderOffset: 14, ChecksumOffset: 40, HeaderStart: 60, HeaderLen: 10},
			wantErr: true,
		},
		{
			name:    "wildly_out_of_range",
			cs:      guest.ChecksumSpec{IPHeaderOffset: 60000, ChecksumOffset: 60000, HeaderStart: 60000, HeaderLen: 60000},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChecksumSpec(tt.cs, dataLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateChecksumSpec(%+v, %d) error = %v, wantErr %v", tt.cs, dataLen, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateOTLP(t *testing.T) {
	// Server mode (recv only) skips sender-specific validations, which makes
	// it the smallest valid baseline for exercising the OTLP checks that run
	// before the server-mode early return.
	base := func() Config {
		return Config{Device: "eth0", Receiver: true, Sender: false}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "otlp_disabled_ignores_other_otlp_flags",
			mutate: func(c *Config) { c.OTLPInterval = 0; c.OTLPAttributes = "not-key-value" },
		},
		{
			name: "otlp_enabled_valid",
			mutate: func(c *Config) {
				c.OTLPEndpoint = "localhost:4317"
				c.OTLPInterval = 10 * time.Second
				c.OTLPAttributes = "site=lab1"
			},
		},
		{
			name: "otlp_enabled_zero_interval",
			mutate: func(c *Config) {
				c.OTLPEndpoint = "localhost:4317"
				c.OTLPInterval = 0
			},
			wantErr: true,
		},
		{
			name: "otlp_enabled_negative_interval",
			mutate: func(c *Config) {
				c.OTLPEndpoint = "localhost:4317"
				c.OTLPInterval = -time.Second
			},
			wantErr: true,
		},
		{
			name: "otlp_enabled_bad_attributes",
			mutate: func(c *Config) {
				c.OTLPEndpoint = "localhost:4317"
				c.OTLPInterval = 10 * time.Second
				c.OTLPAttributes = "not-key-value"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateXDPMode(t *testing.T) {
	// Server mode (recv only) is the smallest valid baseline; the XDP mode
	// check runs before the server-mode early return.
	base := func() Config {
		return Config{Device: "eth0", Receiver: true, Sender: false}
	}

	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "empty_defaults_to_auto", mode: ""},
		{name: "auto", mode: "auto"},
		{name: "native", mode: "native"},
		{name: "generic", mode: "generic"},
		{name: "unknown_mode", mode: "offload", wantErr: true},
		{name: "case_sensitive", mode: "Native", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			c.XDPMode = tt.mode
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseXDPMode(t *testing.T) {
	tests := []struct {
		in      string
		want    XDPMode
		wantErr bool
	}{
		{in: "", want: XDPModeAuto},
		{in: "auto", want: XDPModeAuto},
		{in: "native", want: XDPModeNative},
		{in: "generic", want: XDPModeGeneric},
		{in: "offload", wantErr: true},
		{in: "Native", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseXDPMode(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseXDPMode(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseXDPMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestConfigNormalizeXDPMode(t *testing.T) {
	c := Config{}
	c.Normalize()
	if c.XDPMode != XDPModeAuto.String() {
		t.Errorf("Normalize() XDPMode = %q, want %q", c.XDPMode, XDPModeAuto.String())
	}

	c = Config{XDPMode: "generic"}
	c.Normalize()
	if c.XDPMode != "generic" {
		t.Errorf("Normalize() overwrote XDPMode = %q, want %q", c.XDPMode, "generic")
	}
}

func TestSafeDelta(t *testing.T) {
	tests := []struct {
		name      string
		cur, prev uint64
		want      uint64
	}{
		{"normal", 100, 40, 60},
		{"equal", 50, 50, 0},
		{"reset_to_zero", 0, 1000, 0},
		{"wrap_cur_below_prev", 5, 18446744073709551610, 0}, // would underflow to a huge value
		{"from_zero", 7, 0, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeDelta(tt.cur, tt.prev); got != tt.want {
				t.Errorf("safeDelta(%d, %d) = %d, want %d", tt.cur, tt.prev, got, tt.want)
			}
		})
	}
}
