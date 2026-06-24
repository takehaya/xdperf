package xdperf

import (
	"testing"

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
