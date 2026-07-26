package guest

import (
	"reflect"
	"testing"
)

func TestIPv4UDPChecksumSpecs(t *testing.T) {
	// Untagged Ethernet/IPv4/UDP frame: IPv4 header begins at 14. These are the
	// absolute offsets the reference plugins previously hard-coded; the helper
	// must reproduce them exactly.
	got := IPv4UDPChecksumSpecs(EthernetHeaderLen)
	want := []ChecksumSpec{
		{ChecksumOffset: 24, HeaderStart: 14, HeaderLen: 20, IPHeaderOffset: 14},
		{ChecksumOffset: 40, HeaderStart: 34, HeaderLen: 0, IPHeaderOffset: 14},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPv4UDPChecksumSpecs(14) = %+v, want %+v", got, want)
	}
}

func TestIPv6TransportChecksumSpec(t *testing.T) {
	// Untagged Ethernet/IPv6/UDP frame: IPv6 header at 14, UDP at 54. HeaderLen
	// must stay 0 (data plane derives the transport length) and IPHeaderOffset
	// must point at the IPv6 header for the pseudo-header source.
	got := IPv6TransportChecksumSpec(EthernetHeaderLen, EthernetHeaderLen+IPv6HeaderLen, UDPChecksumFieldOffset)
	want := ChecksumSpec{ChecksumOffset: 60, HeaderStart: 54, HeaderLen: 0, IPHeaderOffset: 14}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPv6TransportChecksumSpec(14, 54, 6) = %+v, want %+v", got, want)
	}

	// TCP variant: only the checksum-field offset shifts.
	got = IPv6TransportChecksumSpec(EthernetHeaderLen, EthernetHeaderLen+IPv6HeaderLen, TCPChecksumFieldOffset)
	want = ChecksumSpec{ChecksumOffset: 70, HeaderStart: 54, HeaderLen: 0, IPHeaderOffset: 14}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPv6TransportChecksumSpec(14, 54, 16) = %+v, want %+v", got, want)
	}
}
