package xdperf

import (
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
)

// buildIPv4Packet returns a minimal IPv4 packet header (no payload) for testing.
// Sets version=4 at ipOff, protocol at ipOff+9.
func buildIPv4Packet(ipOff int, protocol uint8) []byte {
	pkt := make([]byte, ipOff+ipv4HeaderSize+20) // room for transport header
	pkt[ipOff] = 0x45                             // version=4, IHL=5
	pkt[ipOff+ipv4ProtocolOffset] = protocol
	return pkt
}

// buildIPv6Packet returns a minimal IPv6 packet header for testing.
func buildIPv6Packet(ipOff int, nextHeader uint8) []byte {
	pkt := make([]byte, ipOff+ipv6HeaderSize+20)
	pkt[ipOff] = 0x60 // version=6
	pkt[ipOff+ipv6NextHeaderOffset] = nextHeader
	return pkt
}

func TestDiffAffectsChecksum_IPv4Header(t *testing.T) {
	// IPv4 header checksum covers [14, 34). csum_offset = 14+10 = 24.
	const ipOff = 14
	pkt := buildIPv4Packet(ipOff, 17) // UDP

	csumMeta := guest.ChecksumSpec{
		ChecksumOffset: ipOff + ipv4ChecksumFieldOffset, // 24 — marks this as IPv4 header csum
		HeaderStart:    ipOff,
		IPHeaderOffset: ipOff,
	}

	tests := []struct {
		name   string
		offset uint16
		size   uint8
		want   bool
	}{
		{"inside IP header (TTL at 22)", 22, 1, true},
		{"start of IP header", 14, 2, true},
		{"end of IP header (byte 33)", 33, 1, true},
		{"just outside IP header (byte 34)", 34, 2, false},
		{"before IP header (byte 12)", 12, 2, true}, // overlaps with [14,34)
		{"completely before", 0, 10, false},
		{"UDP port (offset 36)", 36, 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := DiffValue{Offset: tt.offset, Size: tt.size}
			got := diffAffectsChecksum(dv, csumMeta, pkt, uint16(len(pkt)))
			if got != tt.want {
				t.Errorf("offset=%d size=%d: got %v, want %v", tt.offset, tt.size, got, tt.want)
			}
		})
	}
}

func TestDiffAffectsChecksum_IPv4Transport(t *testing.T) {
	// UDP checksum: pseudo-header includes src/dst IP [26, 34), transport data [34, pktLen)
	const ipOff = 14
	pkt := buildIPv4Packet(ipOff, 17) // UDP

	csumMeta := guest.ChecksumSpec{
		ChecksumOffset: 40,    // UDP checksum field
		HeaderStart:    34,    // start of UDP header
		IPHeaderOffset: ipOff,
	}
	pktLen := uint16(len(pkt))

	tests := []struct {
		name   string
		offset uint16
		size   uint8
		want   bool
	}{
		{"src IP (offset 26)", 26, 4, true},           // pseudo-header
		{"dst IP (offset 30)", 30, 4, true},           // pseudo-header
		{"TTL (offset 22) — not in pseudo-header", 22, 1, false},
		{"UDP dst port (offset 36)", 36, 2, true},     // transport data
		{"before IP header", 0, 10, false},
		{"Ethernet src MAC (offset 6)", 6, 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := DiffValue{Offset: tt.offset, Size: tt.size}
			got := diffAffectsChecksum(dv, csumMeta, pkt, pktLen)
			if got != tt.want {
				t.Errorf("offset=%d size=%d: got %v, want %v", tt.offset, tt.size, got, tt.want)
			}
		})
	}
}

func TestDiffAffectsChecksum_ICMP(t *testing.T) {
	// ICMP: no pseudo-header, only transport data affects checksum.
	// IP address changes should NOT affect ICMP checksum.
	const ipOff = 14
	pkt := buildIPv4Packet(ipOff, 1) // ICMP

	csumMeta := guest.ChecksumSpec{
		ChecksumOffset: 36,    // ICMP checksum
		HeaderStart:    34,    // start of ICMP header
		IPHeaderOffset: ipOff,
	}
	pktLen := uint16(len(pkt))

	tests := []struct {
		name   string
		offset uint16
		size   uint8
		want   bool
	}{
		{"src IP (offset 26) — ICMP ignores pseudo-header", 26, 4, false},
		{"dst IP (offset 30)", 30, 4, false},
		{"ICMP type (offset 34)", 34, 1, true}, // transport data
		{"ICMP data (offset 38)", 38, 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := DiffValue{Offset: tt.offset, Size: tt.size}
			got := diffAffectsChecksum(dv, csumMeta, pkt, pktLen)
			if got != tt.want {
				t.Errorf("offset=%d size=%d: got %v, want %v", tt.offset, tt.size, got, tt.want)
			}
		})
	}
}

func TestDiffAffectsChecksum_IPv6(t *testing.T) {
	// IPv6 transport: pseudo-header includes src/dst [22, 54), transport data [54, pktLen)
	const ipOff = 14
	pkt := buildIPv6Packet(ipOff, 17) // UDP

	csumMeta := guest.ChecksumSpec{
		ChecksumOffset: 60,    // UDP checksum
		HeaderStart:    54,    // start of UDP header (14+40)
		IPHeaderOffset: ipOff,
	}
	pktLen := uint16(len(pkt))

	tests := []struct {
		name   string
		offset uint16
		size   uint8
		want   bool
	}{
		{"src IPv6 addr (offset 22)", 22, 8, true},    // pseudo-header
		{"dst IPv6 addr (offset 38)", 38, 8, true},    // pseudo-header
		{"hop limit (offset 21) — before saddr", 21, 1, false},
		{"UDP dst port (offset 56)", 56, 2, true},     // transport data
		{"Ethernet header (offset 0)", 0, 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := DiffValue{Offset: tt.offset, Size: tt.size}
			got := diffAffectsChecksum(dv, csumMeta, pkt, pktLen)
			if got != tt.want {
				t.Errorf("offset=%d size=%d: got %v, want %v", tt.offset, tt.size, got, tt.want)
			}
		})
	}
}

func TestDiffAffectsChecksum_Conservative(t *testing.T) {
	// When packet data is too short to read IP version, should return true (conservative)
	shortPkt := make([]byte, 10) // too short for ipOff=14

	cs := guest.ChecksumSpec{IPHeaderOffset: 14}
	dv := DiffValue{Offset: 36, Size: 2}

	got := diffAffectsChecksum(dv, cs, shortPkt, 64)
	if !got {
		t.Error("expected true (conservative) when packet too short, got false")
	}
}
