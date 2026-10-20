// Package vxlan contains value types and codecs derived from vxlan_shared.h.
// No Go memory layout or unsafe casts are part of its ABI.
// Cilium 1.20.3 の段階6の観測側は、数値化した InnerKey の各フィールドを
// ネイティブ順でマップに格納する（x86 ではリトルエンディアン）。
// 外部マップと交換する場合も生成済みオフセットとネイティブ順を使う。
// InnerKey の codec は提供しない。
package vxlan

import "fmt"

// NewHeader implements vxlan_set_vni for valid 24-bit VNIs. Unlike the C
// primitive, it rejects overflow, preserving the Go plugin's input contract.
func NewHeader(vni uint32) (Header, error) {
	if vni > VNIMax {
		return Header{}, fmt.Errorf("vni %d exceeds the 24-bit maximum %d", vni, VNIMax)
	}
	return Header{Flags: FlagVNI, VNI: [HeaderVNISize]uint8{byte(vni >> 16), byte(vni >> 8), byte(vni)}}, nil
}

// VNIValue implements vxlan_vni; protocol flag validation is the caller's job.
func (h Header) VNIValue() uint32 {
	return uint32(h.VNI[0])<<16 | uint32(h.VNI[1])<<8 | uint32(h.VNI[2])
}

// Compile-time checks for the four-byte diff covering reserved byte + VNI.
// The bridge header length must also agree with the C structure.
var (
	_ [HeaderSize - HeaderLen]byte
	_ [HeaderLen - HeaderSize]byte
	_ [HeaderVNISize - 3]byte
	_ [3 - HeaderVNISize]byte
	_ [HeaderVNIOffset - HeaderRsvd0Offset - HeaderRsvd0Size]byte
	_ [HeaderRsvd0Offset + HeaderRsvd0Size - HeaderVNIOffset]byte
	_ [HeaderRsvd0Size - 1]byte
)
