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
