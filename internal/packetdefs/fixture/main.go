package main

import (
	"bytes"
	"fmt"
	"github.com/takehaya/xdperf/pkg/guest/packetdefs/vxlan"
)

// Both toolchains execute these assertions under wazero, without host imports
// beyond WASI and without a C compiler at plugin build time.
func main() {
	for _, vni := range []uint32{0, 1, 0x010203, vxlan.VNIMax} {
		h, err := vxlan.NewHeader(vni)
		if err != nil {
			panic(err)
		}
		b := bytes.Repeat([]byte{0xaa}, 9)
		if err := h.MarshalTo(b); err != nil {
			panic(err)
		}
		want := []byte{8, 0, 0, 0, byte(vni >> 16), byte(vni >> 8), byte(vni), 0, 0xaa}
		if !bytes.Equal(b, want) {
			panic("bytes differ")
		}
		var got vxlan.Header
		if err := got.UnmarshalFrom(b); err != nil {
			panic(err)
		}
		if got != h || got.VNIValue() != vni {
			panic("roundtrip")
		}
		if got.UnmarshalFrom(b[:7]) == nil || got != h {
			panic("short read")
		}
		if h.MarshalTo(b[:7]) == nil || !bytes.Equal(b, want) {
			panic("short write")
		}
	}
	if _, err := vxlan.NewHeader(vxlan.VNIMax + 1); err == nil {
		panic("overflow")
	}
	fmt.Print("packetdefs ok\n")
}
