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
		OuterSrcPort:     2152,
		TEID:             0x11223344,
		EnablePSC:        true,
		PDUTypeUL:        false,
		QFI:              9,
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

func TestBuild5GOffsetsAndStructure(t *testing.T) {
	p := sampleParams()
	const totalLen = 128
	info, err := BuildGTPv1UPacket(p, totalLen)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	if len(info.Data) != totalLen {
		t.Fatalf("frame length = %d, want %d", len(info.Data), totalLen)
	}

	wantOff := map[string]uint64{
		"gtp.start":     42,
		"gtp.teid":      46,
		"psc.qfi":       56,
		"inner.start":   58,
		"inner.udp.src": 78,
	}
	for k, v := range wantOff {
		if info.Offsets[k] != v {
			t.Errorf("offset %s = %d, want %d", k, info.Offsets[k], v)
		}
	}

	d := info.Data
	if d[42] != 0x34 {
		t.Errorf("GTP flags = 0x%02x, want 0x34 (ver1,PT,E)", d[42])
	}
	if d[43] != 0xFF {
		t.Errorf("GTP message type = 0x%02x, want 0xFF (G-PDU)", d[43])
	}
	if teid := binary.BigEndian.Uint32(d[46:50]); teid != p.TEID {
		t.Errorf("TEID = 0x%08x, want 0x%08x", teid, p.TEID)
	}
	if d[53] != 0x85 {
		t.Errorf("next-ext-header-type = 0x%02x, want 0x85 (PSC)", d[53])
	}
	if d[54] != 0x01 {
		t.Errorf("PSC ext length = 0x%02x, want 0x01", d[54])
	}
	if d[55] != 0x00 {
		t.Errorf("PSC octet1 = 0x%02x, want 0x00 (DL)", d[55])
	}
	if d[56] != p.QFI {
		t.Errorf("QFI = %d, want %d", d[56], p.QFI)
	}
	if d[57] != 0x00 {
		t.Errorf("PSC next-ext-type = 0x%02x, want 0x00 (end)", d[57])
	}
}

func TestBuildChecksumsValid(t *testing.T) {
	p := sampleParams()
	info, err := BuildGTPv1UPacket(p, 1400)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	d := info.Data
	const outerIP = 14
	innerIP := int(info.Offsets["inner.start"])

	if !ipv4ChecksumValid(d, outerIP) {
		t.Error("outer IPv4 checksum invalid")
	}
	if !ipv4ChecksumValid(d, innerIP) {
		t.Error("inner IPv4 checksum invalid")
	}
	if !udpChecksumValid(d, outerIP) {
		t.Error("outer UDP checksum invalid")
	}
	if !udpChecksumValid(d, innerIP) {
		t.Error("inner UDP checksum invalid")
	}
}

func TestBuildDecodesWithGopacket(t *testing.T) {
	p := sampleParams()
	info, err := BuildGTPv1UPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	pkt := gopacket.NewPacket(info.Data, layers.LayerTypeEthernet, gopacket.Default)
	gtpLayer := pkt.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer == nil {
		t.Fatalf("gopacket did not decode a GTPv1U layer; layers: %v", pkt.Layers())
	}
	gtp := gtpLayer.(*layers.GTPv1U)
	if gtp.TEID != p.TEID {
		t.Errorf("decoded TEID = 0x%08x, want 0x%08x", gtp.TEID, p.TEID)
	}
	if gtp.MessageType != 0xFF {
		t.Errorf("decoded message type = 0x%02x, want 0xFF", gtp.MessageType)
	}
	if !gtp.ExtensionHeaderFlag {
		t.Error("expected extension header flag set for PSC")
	}
	// The inner IPv4 layer must be present after GTP-U.
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("expected an inner IPv4 layer")
	}
}

func TestBuildClassicNoPSC(t *testing.T) {
	p := sampleParams()
	p.EnablePSC = false
	info, err := BuildGTPv1UPacket(p, 128)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	if got := info.Offsets["inner.start"]; got != 50 {
		t.Errorf("classic inner.start = %d, want 50", got)
	}
	if _, ok := info.Offsets["psc.qfi"]; ok {
		t.Error("psc.qfi offset must be absent when PSC disabled")
	}
	if info.Data[42] != 0x30 {
		t.Errorf("classic GTP flags = 0x%02x, want 0x30 (no E/S/PN)", info.Data[42])
	}
}

func TestChecksumSpecsOrder(t *testing.T) {
	p := sampleParams()
	info, err := BuildGTPv1UPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	specs := info.Checksums
	if len(specs) != 4 {
		t.Fatalf("len(specs) = %d, want 4", len(specs))
	}
	innerOff := uint16(info.Offsets["inner.start"])
	// [0]=outer IPv4, [1]=inner IPv4, [2]=inner UDP, [3]=outer UDP (last).
	if specs[0].IPHeaderOffset != 14 || specs[0].HeaderLen != 20 {
		t.Errorf("spec[0] outer IPv4 wrong: %+v", specs[0])
	}
	if specs[1].IPHeaderOffset != innerOff || specs[1].HeaderLen != 20 {
		t.Errorf("spec[1] inner IPv4 wrong: %+v", specs[1])
	}
	if specs[2].IPHeaderOffset != innerOff || specs[2].HeaderLen != 0 {
		t.Errorf("spec[2] inner UDP wrong: %+v", specs[2])
	}
	if specs[3].IPHeaderOffset != 14 || specs[3].HeaderLen != 0 {
		t.Errorf("spec[3] outer UDP must be last: %+v", specs[3])
	}
}

func TestInnerICMP(t *testing.T) {
	p := sampleParams()
	p.InnerProto = "icmp"
	info, err := BuildGTPv1UPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	d := info.Data
	innerOff := int(info.Offsets["inner.start"]) // 58 for 5G
	icmpOff := innerOff + 20

	if proto := d[innerOff+9]; proto != 1 {
		t.Errorf("inner IP protocol = %d, want 1 (ICMP)", proto)
	}
	if d[icmpOff] != 8 {
		t.Errorf("inner ICMP type = %d, want 8 (echo request)", d[icmpOff])
	}
	// There is no inner UDP port offset; an inner ICMP id/seq offset is present.
	if _, ok := info.Offsets["inner.udp.src"]; ok {
		t.Error("inner.udp.src must be absent for inner ICMP")
	}
	if _, ok := info.Offsets["inner.icmp.id"]; !ok {
		t.Error("inner.icmp.id offset must be present for inner ICMP")
	}

	// The inner ICMP checksum is left to gopacket (no data-plane spec, since the
	// data plane miscomputes ICMPv4 and the inner message is static): expect
	// [outer IPv4, inner IPv4, outer UDP] and no spec targeting the ICMP field.
	if len(info.Checksums) != 3 {
		t.Fatalf("checksums = %d, want 3 (no inner ICMP spec)", len(info.Checksums))
	}
	if info.Checksums[2].IPHeaderOffset != 14 || info.Checksums[2].HeaderLen != 0 {
		t.Errorf("spec[2] must be outer UDP (last): %+v", info.Checksums[2])
	}
	for _, cs := range info.Checksums {
		if int(cs.ChecksumOffset) == icmpOff+2 {
			t.Errorf("inner ICMP checksum must not be a data-plane spec: %+v", cs)
		}
	}

	// The inner ICMP checksum (no pseudo-header) must be valid over the ICMP message.
	innerTotLen := int(binary.BigEndian.Uint16(d[innerOff+2 : innerOff+4]))
	icmpLen := innerTotLen - 20
	if fold(onesComplementSum(d[icmpOff:icmpOff+icmpLen])) != 0xFFFF {
		t.Error("inner ICMP checksum invalid")
	}

	// Outer checksums (which cover the inner ICMP bytes) must still be valid.
	if !ipv4ChecksumValid(d, 14) || !udpChecksumValid(d, 14) {
		t.Error("outer IPv4/UDP checksum invalid for inner-ICMP frame")
	}

	// gopacket must decode an ICMPv4 layer after the GTP-U/inner-IPv4 stack.
	pkt := gopacket.NewPacket(d, layers.LayerTypeEthernet, gopacket.Default)
	if pkt.Layer(layers.LayerTypeICMPv4) == nil {
		t.Errorf("expected an inner ICMPv4 layer; got %v", pkt.Layers())
	}
}

func TestInnerUDPNoChecksum(t *testing.T) {
	p := sampleParams()
	p.InnerUDPChecksum = false
	info, err := BuildGTPv1UPacket(p, 256)
	if err != nil {
		t.Fatalf("BuildGTPv1UPacket: %v", err)
	}
	d := info.Data
	innerOff := int(info.Offsets["inner.start"])
	udpCsumOff := innerOff + 20 + 6

	if d[udpCsumOff] != 0 || d[udpCsumOff+1] != 0 {
		t.Errorf("inner UDP checksum = 0x%02x%02x, want 0 (disabled)", d[udpCsumOff], d[udpCsumOff+1])
	}
	// No inner UDP checksum spec: [outer IPv4, inner IPv4, outer UDP].
	if len(info.Checksums) != 3 {
		t.Fatalf("checksums = %d, want 3 (no inner UDP spec)", len(info.Checksums))
	}
	if info.Checksums[2].IPHeaderOffset != 14 || info.Checksums[2].HeaderLen != 0 {
		t.Errorf("spec[2] must be outer UDP (last): %+v", info.Checksums[2])
	}
	// Outer IPv4/UDP and inner IPv4 checksums remain valid; only the inner UDP
	// checksum is intentionally 0.
	if !ipv4ChecksumValid(d, 14) || !ipv4ChecksumValid(d, innerOff) || !udpChecksumValid(d, 14) {
		t.Error("outer/inner IPv4 or outer UDP checksum invalid")
	}
}

func TestPSCUplinkDownlink(t *testing.T) {
	const octet1, qfiByte = 55, 56 // PSC content octets for the default 5G layout

	// Downlink with RQI set: octet1 PDU type = 0, octet2 = RQI(0x40) | QFI.
	dl := sampleParams()
	dl.PDUTypeUL = false
	dl.RQI = true
	dl.QFI = 9
	dlInfo, err := BuildGTPv1UPacket(dl, 256)
	if err != nil {
		t.Fatalf("DL build: %v", err)
	}
	if dlInfo.Data[octet1] != 0x00 {
		t.Errorf("DL PSC octet1 = 0x%02x, want 0x00 (PDU type 0)", dlInfo.Data[octet1])
	}
	if dlInfo.Data[qfiByte] != 0x40|9 {
		t.Errorf("DL PSC octet2 = 0x%02x, want 0x49 (RQI|QFI)", dlInfo.Data[qfiByte])
	}

	// Uplink with RQI requested: octet1 PDU type = 1, octet2 = QFI only (RQI is
	// downlink-only and must not appear in the uplink container).
	ul := sampleParams()
	ul.PDUTypeUL = true
	ul.RQI = true
	ul.QFI = 9
	ulInfo, err := BuildGTPv1UPacket(ul, 256)
	if err != nil {
		t.Fatalf("UL build: %v", err)
	}
	if ulInfo.Data[octet1] != 0x10 {
		t.Errorf("UL PSC octet1 = 0x%02x, want 0x10 (PDU type 1)", ulInfo.Data[octet1])
	}
	if ulInfo.Data[qfiByte] != 9 {
		t.Errorf("UL PSC octet2 = 0x%02x, want 0x09 (QFI only, no RQI)", ulInfo.Data[qfiByte])
	}
}
