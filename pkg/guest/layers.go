package guest

// Common Ethernet/IP/transport layer sizes and checksum-field offsets. Plugins
// use these to build ChecksumSpec offsets without re-deriving the magic numbers
// in each implementation (mirrors the named-offset pattern the host uses in
// pkg/xdperf/bpf.go), reducing the silent-drift risk of hand-maintained offsets.
const (
	EthernetHeaderLen = 14

	IPv4HeaderLen           = 20
	IPv4ChecksumFieldOffset = 10 // checksum field offset within the IPv4 header
	IPv6HeaderLen           = 40

	UDPHeaderLen           = 8
	UDPChecksumFieldOffset = 6  // checksum field offset within the UDP header
	TCPChecksumFieldOffset = 16 // checksum field offset within the TCP header
)

// IPv4UDPChecksumSpecs returns the standard checksum specs for an
// Ethernet/IPv4/UDP packet whose IPv4 header begins at ipHeaderOffset (typically
// EthernetHeaderLen for an untagged frame): the IPv4 header checksum and the UDP
// checksum, in the layout the data plane expects.
func IPv4UDPChecksumSpecs(ipHeaderOffset uint16) []ChecksumSpec {
	udpStart := ipHeaderOffset + IPv4HeaderLen
	return []ChecksumSpec{
		{
			ChecksumOffset: ipHeaderOffset + IPv4ChecksumFieldOffset,
			HeaderStart:    ipHeaderOffset,
			HeaderLen:      IPv4HeaderLen,
			IPHeaderOffset: ipHeaderOffset,
		},
		{
			ChecksumOffset: udpStart + UDPChecksumFieldOffset,
			HeaderStart:    udpStart,
			HeaderLen:      0, // 0 = computed from IP total length by the data plane
			IPHeaderOffset: ipHeaderOffset,
		},
	}
}
