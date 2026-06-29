package builder

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func sampleParams() PacketParams {
	return PacketParams{
		SrcMAC:           [6]byte{0x02, 0, 0, 0, 0, 0x01},
		DstMAC:           [6]byte{0x02, 0, 0, 0, 0, 0x02},
		SrcIP:            "10.0.0.1",
		DstIP:            "10.0.0.2",
		OuterSrcPort:     12345,
		OuterDstPort:     VXLANPort,
		VNI:              0x010203,
		InnerSrcMAC:      [6]byte{0x02, 0, 0, 0, 0x01, 0x01},
		InnerDstMAC:      [6]byte{0x02, 0, 0, 0, 0x01, 0x02},
		InnerUDPChecksum: true,
		InnerSrcIP:       "192.168.0.1",
		InnerDstIP:       "192.168.0.2",
		InnerSrcPort:     1024,
		InnerDstPort:     5060,
	}
}

func onesComplementSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// ipv4ChecksumValid returns true when the IPv4 header at ipOff carries a valid
// header checksum (one's-complement sum over the header folds to 0xFFFF).
func ipv4ChecksumValid(b []byte, ipOff int) bool {
	ihl := int(b[ipOff]&0x0F) * 4
	return fold(onesComplementSum(b[ipOff:ipOff+ihl])) == 0xFFFF
}

// udpChecksumValid validates the UDP checksum of the datagram whose IPv4 header
// starts at ipOff, using the IPv4 pseudo-header.
func udpChecksumValid(b []byte, ipOff int) bool {
	ihl := int(b[ipOff]&0x0F) * 4
	totalLen := int(binary.BigEndian.Uint16(b[ipOff+2 : ipOff+4]))
	udpOff := ipOff + ihl
	udpSegLen := totalLen - ihl
	if udpOff+udpSegLen > len(b) {
		return false
	}
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], b[ipOff+12:ipOff+16])
	copy(pseudo[4:8], b[ipOff+16:ipOff+20])
	pseudo[9] = b[ipOff+9] // protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpSegLen))
	sum := onesComplementSum(pseudo) + onesComplementSum(b[udpOff:udpOff+udpSegLen])
	return fold(sum) == 0xFFFF
}

func TestBuildOffsetsAndStructure(t *testing.T) {
	p := sampleParams()
	const totalLen = 128
	info, err := BuildVXLANPacket(p, totalLen)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	if len(info.Data) != totalLen {
		t.Fatalf("frame length = %d, want %d", len(info.Data), totalLen)
	}

	wantOff := map[string]uint64{
		"outer.udp.src":  34,
		"vxlan.start":    42,
		"vxlan.vni":      46,
		"inner.start":    50,
		"inner.ip.start": 64,
		"inner.ip.src":   76,
		"inner.ip.dst":   80,
		"inner.udp.src":  84,
	}
	for k, v := range wantOff {
		if info.Offsets[k] != v {
			t.Errorf("offset %s = %d, want %d", k, info.Offsets[k], v)
		}
	}

	d := info.Data
	// Outer UDP destination port = VXLAN port.
	if dport := binary.BigEndian.Uint16(d[36:38]); dport != VXLANPort {
		t.Errorf("outer UDP dst port = %d, want %d", dport, VXLANPort)
	}
	// VXLAN flags: I bit set.
	if d[42] != 0x08 {
		t.Errorf("VXLAN flags = 0x%02x, want 0x08 (I bit)", d[42])
	}
	// VXLAN reserved bytes 43..45 are 0.
	if d[43] != 0 || d[44] != 0 || d[45] != 0 {
		t.Errorf("VXLAN reserved word 0 not zero: %02x %02x %02x", d[43], d[44], d[45])
	}
	// VNI 24-bit big-endian at 46..48.
	vni := uint32(d[46])<<16 | uint32(d[47])<<8 | uint32(d[48])
	if vni != p.VNI {
		t.Errorf("VNI = 0x%06x, want 0x%06x", vni, p.VNI)
	}
	// Trailing reserved byte at 49 is 0.
	if d[49] != 0 {
		t.Errorf("VXLAN trailing reserved = 0x%02x, want 0", d[49])
	}
	// Inner Ethernet type at 50+12 = 62..63 is IPv4 (0x0800).
	if et := binary.BigEndian.Uint16(d[62:64]); et != 0x0800 {
		t.Errorf("inner EtherType = 0x%04x, want 0x0800 (IPv4)", et)
	}
}

func TestOuterUDPChecksumIsZero(t *testing.T) {
	p := sampleParams()
	info, err := BuildVXLANPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	d := info.Data
	// Outer UDP checksum field at 34+6 = 40..41 must be 0 (RFC 7348 default).
	if d[40] != 0 || d[41] != 0 {
		t.Errorf("outer UDP checksum = 0x%02x%02x, want 0", d[40], d[41])
	}
}

func TestBuildChecksumsValid(t *testing.T) {
	p := sampleParams()
	info, err := BuildVXLANPacket(p, 1400)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	d := info.Data
	const outerIP = 14
	innerIP := int(info.Offsets["inner.ip.start"])

	if !ipv4ChecksumValid(d, outerIP) {
		t.Error("outer IPv4 checksum invalid")
	}
	if !ipv4ChecksumValid(d, innerIP) {
		t.Error("inner IPv4 checksum invalid")
	}
	if !udpChecksumValid(d, innerIP) {
		t.Error("inner UDP checksum invalid")
	}
}

func TestChecksumSpecs(t *testing.T) {
	p := sampleParams()
	info, err := BuildVXLANPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	specs := info.Checksums
	// Inner UDP checksum enabled: [outer IPv4, inner IPv4, inner UDP]. No outer
	// UDP spec (VXLAN leaves it 0).
	if len(specs) != 3 {
		t.Fatalf("len(specs) = %d, want 3", len(specs))
	}
	innerOff := uint16(info.Offsets["inner.ip.start"])
	if specs[0].IPHeaderOffset != 14 || specs[0].HeaderLen != 20 {
		t.Errorf("spec[0] outer IPv4 wrong: %+v", specs[0])
	}
	if specs[1].IPHeaderOffset != innerOff || specs[1].HeaderLen != 20 {
		t.Errorf("spec[1] inner IPv4 wrong: %+v", specs[1])
	}
	if specs[2].IPHeaderOffset != innerOff || specs[2].HeaderLen != 0 {
		t.Errorf("spec[2] inner UDP wrong: %+v", specs[2])
	}
	// No spec may target the outer UDP checksum (offset 40).
	for _, cs := range specs {
		if cs.ChecksumOffset == 40 {
			t.Errorf("outer UDP must not have a checksum spec: %+v", cs)
		}
	}
}

func TestInnerUDPNoChecksum(t *testing.T) {
	p := sampleParams()
	p.InnerUDPChecksum = false
	info, err := BuildVXLANPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	d := info.Data
	innerOff := int(info.Offsets["inner.ip.start"])
	udpCsumOff := innerOff + 20 + 6

	if d[udpCsumOff] != 0 || d[udpCsumOff+1] != 0 {
		t.Errorf("inner UDP checksum = 0x%02x%02x, want 0 (disabled)", d[udpCsumOff], d[udpCsumOff+1])
	}
	// No inner UDP checksum spec: [outer IPv4, inner IPv4].
	if len(info.Checksums) != 2 {
		t.Fatalf("checksums = %d, want 2 (no inner UDP spec)", len(info.Checksums))
	}
	// Outer/inner IPv4 checksums remain valid; only the inner UDP checksum is 0.
	if !ipv4ChecksumValid(d, 14) || !ipv4ChecksumValid(d, innerOff) {
		t.Error("outer/inner IPv4 checksum invalid")
	}
}

func TestBuildDecodesWithGopacket(t *testing.T) {
	p := sampleParams()
	info, err := BuildVXLANPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	pkt := gopacket.NewPacket(info.Data, layers.LayerTypeEthernet, gopacket.Default)
	vxLayer := pkt.Layer(layers.LayerTypeVXLAN)
	if vxLayer == nil {
		t.Fatalf("gopacket did not decode a VXLAN layer; layers: %v", pkt.Layers())
	}
	vx := vxLayer.(*layers.VXLAN)
	if !vx.ValidIDFlag {
		t.Error("expected VXLAN I (valid VNI) flag set")
	}
	if vx.VNI != p.VNI {
		t.Errorf("decoded VNI = 0x%06x, want 0x%06x", vx.VNI, p.VNI)
	}
	// The inner Ethernet + IPv4 must decode after VXLAN.
	if pkt.Layer(layers.LayerTypeEthernet) == nil {
		t.Error("expected an inner Ethernet layer")
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("expected an inner IPv4 layer")
	}
}

func TestVNIRangeRejected(t *testing.T) {
	p := sampleParams()
	p.VNI = 0x1000000 // 2^24, out of range
	if _, err := BuildVXLANPacket(p, 256); err == nil {
		t.Error("expected an error for out-of-range VNI")
	}
}

func TestInnerL2Only64B(t *testing.T) {
	p := sampleParams()
	p.InnerL2Only = true
	if min := MinFrameLen(p); min != 64 {
		t.Fatalf("l2only MinFrameLen = %d, want 64", min)
	}
	info, err := BuildVXLANPacket(p, 64)
	if err != nil {
		t.Fatalf("BuildVXLANPacket l2only 64B: %v", err)
	}
	if len(info.Data) != 64 {
		t.Fatalf("frame length = %d, want 64", len(info.Data))
	}
	d := info.Data
	// Outer stack intact: UDP dst 4789, checksum 0, VXLAN flags + VNI.
	if dport := binary.BigEndian.Uint16(d[36:38]); dport != VXLANPort {
		t.Errorf("outer UDP dst = %d, want %d", dport, VXLANPort)
	}
	if d[40] != 0 || d[41] != 0 {
		t.Errorf("outer UDP checksum = 0x%02x%02x, want 0", d[40], d[41])
	}
	if d[42] != 0x08 {
		t.Errorf("VXLAN flags = 0x%02x, want 0x08", d[42])
	}
	vni := uint32(d[46])<<16 | uint32(d[47])<<8 | uint32(d[48])
	if vni != p.VNI {
		t.Errorf("VNI = 0x%06x, want 0x%06x", vni, p.VNI)
	}
	// Inner Ethernet at offset 50: dst/src MAC, EtherType 0x0000.
	innerEth := int(info.Offsets["inner.start"])
	if innerEth != 50 {
		t.Fatalf("inner.start = %d, want 50", innerEth)
	}
	if et := binary.BigEndian.Uint16(d[innerEth+12 : innerEth+14]); et != 0x0000 {
		t.Errorf("inner EtherType = 0x%04x, want 0x0000 (no L3)", et)
	}
	// No inner L3/L4 offsets in l2only mode.
	for _, k := range []string{"inner.ip.start", "inner.ip.src", "inner.udp.src"} {
		if _, ok := info.Offsets[k]; ok {
			t.Errorf("offset %q must be absent in l2only mode", k)
		}
	}
	// L2-only: only the outer IPv4 checksum spec (no inner L3/L4), and it stays
	// valid on the wire.
	if len(info.Checksums) != 1 {
		t.Fatalf("checksums = %d, want 1 (outer IPv4 only)", len(info.Checksums))
	}
	if !ipv4ChecksumValid(d, 14) {
		t.Error("outer IPv4 checksum invalid")
	}
}

func TestOuterVLANTag(t *testing.T) {
	p := sampleParams()
	p.VLANID = 100
	p.VLANPCP = 3
	if min := MinFrameLen(p); min != 96 {
		t.Fatalf("tagged MinFrameLen = %d, want 96 (92+4)", min)
	}
	info, err := BuildVXLANPacket(p, 128)
	if err != nil {
		t.Fatalf("BuildVXLANPacket tagged: %v", err)
	}
	d := info.Data
	// Outer Ethernet EtherType is 802.1Q (0x8100) at offset 12.
	if et := binary.BigEndian.Uint16(d[12:14]); et != 0x8100 {
		t.Errorf("EtherType = 0x%04x, want 0x8100 (802.1Q)", et)
	}
	// 802.1Q TCI at offset 14: PCP (top 3 bits) and VID (low 12 bits).
	tci := binary.BigEndian.Uint16(d[14:16])
	if vid := tci & 0x0FFF; vid != 100 {
		t.Errorf("VLAN VID = %d, want 100", vid)
	}
	if pcp := tci >> 13; pcp != 3 {
		t.Errorf("VLAN PCP = %d, want 3", pcp)
	}
	// vlan.tci offset is exposed only when tagged.
	if info.Offsets["vlan.tci"] != 14 {
		t.Errorf("vlan.tci offset = %d, want 14", info.Offsets["vlan.tci"])
	}
	// Every downstream offset is shifted by the 4-byte tag.
	want := map[string]uint64{
		"outer.udp.src":  38,
		"vxlan.start":    46,
		"vxlan.vni":      50,
		"inner.start":    54,
		"inner.ip.start": 68,
		"inner.udp.src":  88,
	}
	for k, v := range want {
		if info.Offsets[k] != v {
			t.Errorf("tagged offset %s = %d, want %d", k, info.Offsets[k], v)
		}
	}
	// Outer IPv4 (now at offset 18) and inner IPv4 checksums stay valid.
	if !ipv4ChecksumValid(d, 18) {
		t.Error("outer IPv4 checksum invalid (tagged)")
	}
	if !ipv4ChecksumValid(d, 68) {
		t.Error("inner IPv4 checksum invalid (tagged)")
	}
	// The outer IPv4 checksum spec must target the shifted header (offset 18+10).
	if info.Checksums[0].ChecksumOffset != 18+10 {
		t.Errorf("outer IPv4 spec ChecksumOffset = %d, want 28", info.Checksums[0].ChecksumOffset)
	}
}

func TestVLANUntaggedByDefault(t *testing.T) {
	p := sampleParams() // VLANID == 0
	info, err := BuildVXLANPacket(p, 128)
	if err != nil {
		t.Fatalf("BuildVXLANPacket: %v", err)
	}
	// No tag: EtherType is IPv4 directly, no vlan.tci offset, VNI stays at 46.
	if et := binary.BigEndian.Uint16(info.Data[12:14]); et != 0x0800 {
		t.Errorf("untagged EtherType = 0x%04x, want 0x0800 (IPv4)", et)
	}
	if _, ok := info.Offsets["vlan.tci"]; ok {
		t.Error("vlan.tci offset must be absent when untagged")
	}
	if info.Offsets["vxlan.vni"] != 46 {
		t.Errorf("untagged vxlan.vni = %d, want 46", info.Offsets["vxlan.vni"])
	}
}

func TestBelowMinFrameLen(t *testing.T) {
	p := sampleParams()
	min := MinFrameLen(p)
	if min != 92 {
		t.Errorf("MinFrameLen = %d, want 92", min)
	}
	if _, err := BuildVXLANPacket(p, min-1); err == nil {
		t.Error("expected an error for frame below the minimum length")
	}
}
