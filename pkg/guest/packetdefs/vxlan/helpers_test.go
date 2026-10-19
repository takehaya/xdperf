package vxlan

import (
	"bytes"
	"testing"
)

func TestHeaderCodec(t *testing.T) {
	for _, vni := range []uint32{0, 1, 0x010203, VNIMax} {
		h, err := NewHeader(vni)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{8, 0, 0, 0, byte(vni >> 16), byte(vni >> 8), byte(vni), 0, 0xaa}
		dst := bytes.Repeat([]byte{0xaa}, 9)
		if err := h.MarshalTo(dst); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst, want) {
			t.Fatalf("%x want %x", dst, want)
		}
		var got Header
		if err := got.UnmarshalFrom(dst); err != nil {
			t.Fatal(err)
		}
		if got != h || got.VNIValue() != vni {
			t.Fatal(got)
		}
		dst[4] ^= 0xff
		if got != h {
			t.Fatal("input alias")
		}
		if got.UnmarshalFrom(dst[:7]) == nil || got != h {
			t.Fatal("short read changed receiver")
		}
		old := append([]byte(nil), dst...)
		if h.MarshalTo(dst[:7]) == nil || !bytes.Equal(dst, old) {
			t.Fatal("short write changed buffer")
		}
	}
	if _, err := NewHeader(VNIMax + 1); err == nil {
		t.Fatal("overflow accepted")
	}
	// Generic codecs preserve noncanonical reserved bytes and flags.
	h := Header{Flags: 0xfe, Rsvd0: [3]uint8{1, 2, 3}, VNI: [3]uint8{4, 5, 6}, Rsvd1: 7}
	buf := make([]byte, 8)
	if err := h.MarshalTo(buf); err != nil {
		t.Fatal(err)
	}
	var got Header
	if err := got.UnmarshalFrom(buf); err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatal(got)
	}
}
