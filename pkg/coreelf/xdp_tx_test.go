package coreelf

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	xdpTx               = 3          // XDP_TX return code
	lastBaseIdxSentinel  = 0xFFFFFFFF // Must match pkt_state initial value
)

func loadWithDiffMap(t *testing.T, diffMapSize uint32) *BpfObjects {
	t.Helper()
	objs, _, err := ReadCollection(defaultConsts(), diffMapSize)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("ReadCollection failed: %+v", ve)
		}
		t.Fatalf("ReadCollection failed: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return objs
}

// buildUDPPacketSized creates an IPv4/UDP packet with the given dst port and total size.
func buildUDPPacketSized(t *testing.T, dstPort uint16, totalSize int) []byte {
	t.Helper()
	headerSize := 14 + 20 + 8 // eth + ip + udp
	if totalSize < headerSize {
		t.Fatalf("totalSize %d < minimum header size %d", totalSize, headerSize)
	}
	payloadSize := totalSize - headerSize

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	payload := make([]byte, payloadSize)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

// buildUDPPacketWithTTL creates an IPv4/UDP packet with custom TTL, dst port, and size.
func buildUDPPacketWithTTL(t *testing.T, dstPort uint16, ttl uint8, totalSize int) []byte {
	t.Helper()
	headerSize := 14 + 20 + 8
	eth := &layers.Ethernet{
		SrcMAC: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, DstMAC: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: ttl, Protocol: layers.IPProtocolUDP,
		SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 12345, DstPort: layers.UDPPort(dstPort)}
	udp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, totalSize-headerSize)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

// buildUDPPacket creates a minimal IPv4/UDP packet with the given dst port (64 bytes).
func buildUDPPacket(t *testing.T, dstPort uint16) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Pad payload to reach 64 bytes minimum (COPY_CHUNK_SIZE)
	payload := make([]byte, 22) // 14(eth) + 20(ip) + 8(udp) + 22(payload) = 64

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

// runXdpTx executes the xdp_tx program via BPF_PROG_TEST_RUN.
func runXdpTx(t *testing.T, prog *ebpf.Program, inputPkt []byte) (retCode uint32, outputPkt []byte) {
	t.Helper()
	return runXdpTxExpectLen(t, prog, inputPkt, len(inputPkt))
}

// runXdpTxExpectLen executes xdp_tx and returns output truncated/padded to expectedLen.
func runXdpTxExpectLen(t *testing.T, prog *ebpf.Program, inputPkt []byte, expectedLen int) (retCode uint32, outputPkt []byte) {
	t.Helper()

	dataOut := make([]byte, expectedLen+256)
	opts := &ebpf.RunOptions{
		Data:    inputPkt,
		DataOut: dataOut,
		Context: XdpMd{DataEnd: uint32(len(inputPkt))},
	}
	ret, err := prog.Run(opts)
	if err != nil {
		t.Fatalf("prog.Run: %v", err)
	}
	// opts.DataOut may have been resized by cilium/ebpf to actual output length
	out := opts.DataOut
	if len(out) > expectedLen {
		out = out[:expectedLen]
	}
	return ret, out
}

// TestXdpTxCopySkip verifies that when xdp_tx skips the base packet copy
// (same base_idx, same length), the output packet is still correct.
func TestXdpTxCopySkip(t *testing.T) {
	objs := loadWithDiffMap(t, 2)

	// Build base packet with dst port 80
	basePkt := buildUDPPacket(t, 80)
	pktLen := len(basePkt)

	// UDP dst port is at offset 36 (14 eth + 20 ip + 2 src_port = 36)
	const udpDstPortOffset = 36

	// Read base packet's value at the dst port offset
	var basePortBytes [8]uint8
	basePortBytes[0] = basePkt[udpDstPortOffset]
	basePortBytes[1] = basePkt[udpDstPortOffset+1]

	// Diff entry 0: change dst port to 8080 (0x1F90)
	var newPort0 [8]uint8
	binary.BigEndian.PutUint16(newPort0[:], 8080)

	// Diff entry 1: change dst port to 9090 (0x2382)
	var newPort1 [8]uint8
	binary.BigEndian.PutUint16(newPort1[:], 9090)

	// IPv4 header checksum: csum_offset = 14+10 = 24
	// UDP checksum: csum_offset = 14+20+6 = 40
	csumMeta := []BpfChecksumMeta{
		{CsumOffset: 24, HeaderStart: 14, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 0},  // IPv4 header checksum
		{CsumOffset: 40, HeaderStart: 34, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 17}, // UDP checksum (17=IPPROTO_UDP)
	}

	numCPUs := ebpf.MustPossibleCPU()

	// --- Set up diff_map entry 0: port -> 8080 ---
	entry0 := BpfDiffEntry{
		PktLen:    uint16(pktLen),
		BaseIdx:   0,
		DiffCount: 1,
	}
	// UDP port at offset 36: outside IPv4 header [14,34) → bit0=0
	// inside UDP transport [34,64) → bit1=1 → affects_csum = 0x02
	entry0.Diffs[0].Offset = udpDstPortOffset
	entry0.Diffs[0].Size = 2
	entry0.Diffs[0].OldValue = basePortBytes
	entry0.Diffs[0].NewValue = newPort0
	entry0.Diffs[0].AffectsCsum = 0x02

	// --- Set up diff_map entry 1: port -> 9090 ---
	entry1 := BpfDiffEntry{
		PktLen:    uint16(pktLen),
		BaseIdx:   0,
		DiffCount: 1,
	}
	entry1.Diffs[0].Offset = udpDstPortOffset
	entry1.Diffs[0].Size = 2
	entry1.Diffs[0].OldValue = basePortBytes
	entry1.Diffs[0].NewValue = newPort1
	entry1.Diffs[0].AffectsCsum = 0x02

	// Write diff entries
	entries0 := make([]BpfDiffEntry, numCPUs)
	entries1 := make([]BpfDiffEntry, numCPUs)
	for i := range entries0 {
		entries0[i] = entry0
		entries1[i] = entry1
	}
	k0, k1 := uint32(0), uint32(1)
	if err := objs.DiffMap.Put(&k0, entries0); err != nil {
		t.Fatalf("diff_map put[0]: %v", err)
	}
	if err := objs.DiffMap.Put(&k1, entries1); err != nil {
		t.Fatalf("diff_map put[1]: %v", err)
	}

	// Write base packet map
	base := BpfBasePacket{
		Len:           uint16(pktLen),
		ChecksumCount: uint8(len(csumMeta)),
	}
	copy(base.Data[:], basePkt)
	bases := make([]BpfBasePacket, numCPUs)
	for i := range bases {
		bases[i] = base
	}
	key := uint32(0)
	if err := objs.BasePacketMap.Put(&key, bases); err != nil {
		t.Fatalf("base_packet_map put: %v", err)
	}

	// Write checksum meta
	for i, meta := range csumMeta {
		metas := make([]BpfChecksumMeta, numCPUs)
		for j := range metas {
			metas[j] = meta
		}
		k := uint32(i)
		if err := objs.ChecksumMetaMap.Put(&k, metas); err != nil {
			t.Fatalf("checksum_meta_map put[%d]: %v", i, err)
		}
	}

	// Write pkt_state: count=2, idx=0, last_base_idx=sentinel
	states := make([]BpfPktState, numCPUs)
	for i := range states {
		states[i] = BpfPktState{Count: 2, Idx: 0, LastBaseIdx: lastBaseIdxSentinel}
	}
	if err := objs.PktStateMap.Put(&key, states); err != nil {
		t.Fatalf("pkt_state_map put: %v", err)
	}

	// === Run 1: First execution (copy should happen, idx=0 → port 8080) ===
	ret1, out1 := runXdpTx(t, objs.XdpTx, basePkt)
	if ret1 != xdpTx {
		t.Fatalf("run 1: got XDP action %d, want XDP_TX (%d)", ret1, xdpTx)
	}

	// Verify dst port = 8080
	gotPort1 := binary.BigEndian.Uint16(out1[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort1 != 8080 {
		t.Errorf("run 1: dst port = %d, want 8080", gotPort1)
	}

	// Build expected packet (base with port 8080) to compare checksums
	expectedPkt1 := buildUDPPacket(t, 8080)
	verifyChecksums(t, "run 1", out1, expectedPkt1)

	// === Run 2: Second execution (copy should be SKIPPED, idx=1 → port 9090) ===
	// Feed the output of run 1 as input — simulates XDP TX packet recycling
	ret2, out2 := runXdpTx(t, objs.XdpTx, out1)
	if ret2 != xdpTx {
		t.Fatalf("run 2: got XDP action %d, want XDP_TX (%d)", ret2, xdpTx)
	}

	// Verify dst port = 9090
	gotPort2 := binary.BigEndian.Uint16(out2[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort2 != 9090 {
		t.Errorf("run 2 (copy skipped): dst port = %d, want 9090", gotPort2)
	}

	// Build expected packet (base with port 9090) to compare checksums
	expectedPkt2 := buildUDPPacket(t, 9090)
	verifyChecksums(t, "run 2 (copy skipped)", out2, expectedPkt2)

	// === Verify stats: no errors ===
	var stats []BpfDatarec
	if err := objs.TxStatsMap.Lookup(&key, &stats); err != nil {
		t.Fatalf("tx_stats_map lookup: %v", err)
	}
	var totalDiffErrors, totalCsumErrors uint64
	for _, s := range stats {
		totalDiffErrors += s.DiffErrors
		totalCsumErrors += s.ChecksumErrors
	}
	if totalDiffErrors != 0 {
		t.Errorf("diff_errors = %d, want 0", totalDiffErrors)
	}
	if totalCsumErrors != 0 {
		t.Errorf("checksum_errors = %d, want 0", totalCsumErrors)
	}
}

// verifyChecksums compares IPv4 header and UDP checksums between actual and expected packets.
func verifyChecksums(t *testing.T, label string, actual, expected []byte) {
	t.Helper()

	// IPv4 header checksum at offset 24 (14 eth + 10)
	actualIPCsum := binary.BigEndian.Uint16(actual[24:26])
	expectedIPCsum := binary.BigEndian.Uint16(expected[24:26])
	if actualIPCsum != expectedIPCsum {
		t.Errorf("%s: IPv4 checksum = 0x%04x, want 0x%04x", label, actualIPCsum, expectedIPCsum)
	}

	// UDP checksum at offset 40 (14 eth + 20 ip + 6)
	actualUDPCsum := binary.BigEndian.Uint16(actual[40:42])
	expectedUDPCsum := binary.BigEndian.Uint16(expected[40:42])
	if actualUDPCsum != expectedUDPCsum {
		t.Errorf("%s: UDP checksum = 0x%04x, want 0x%04x", label, actualUDPCsum, expectedUDPCsum)
	}
}

// TestXdpTxCopyOnBaseChange verifies that changing base_idx forces a copy.
func TestXdpTxCopyOnBaseChange(t *testing.T) {
	objs := loadWithDiffMap(t, 2)

	// Build two different base packets
	basePkt0 := buildUDPPacket(t, 80)   // base 0: port 80
	basePkt1 := buildUDPPacket(t, 443)  // base 1: port 443
	pktLen := len(basePkt0)

	numCPUs := ebpf.MustPossibleCPU()
	key := uint32(0)

	// Write two base packets
	for idx, pkt := range [][]byte{basePkt0, basePkt1} {
		base := BpfBasePacket{
			Len:           uint16(len(pkt)),
			ChecksumCount: 0, // no checksums for simplicity
		}
		copy(base.Data[:], pkt)
		bases := make([]BpfBasePacket, numCPUs)
		for i := range bases {
			bases[i] = base
		}
		k := uint32(idx)
		if err := objs.BasePacketMap.Put(&k, bases); err != nil {
			t.Fatalf("base_packet_map put[%d]: %v", idx, err)
		}
	}

	// Diff entry 0: base_idx=0, no diffs
	// Diff entry 1: base_idx=1, no diffs
	for idx := 0; idx < 2; idx++ {
		entry := BpfDiffEntry{
			PktLen:    uint16(pktLen),
			BaseIdx:   uint8(idx),
			DiffCount: 0,
		}
		entries := make([]BpfDiffEntry, numCPUs)
		for i := range entries {
			entries[i] = entry
		}
		k := uint32(idx)
		if err := objs.DiffMap.Put(&k, entries); err != nil {
			t.Fatalf("diff_map put[%d]: %v", idx, err)
		}
	}

	// pkt_state: count=2, idx=0
	states := make([]BpfPktState, numCPUs)
	for i := range states {
		states[i] = BpfPktState{Count: 2, Idx: 0, LastBaseIdx: lastBaseIdxSentinel}
	}
	if err := objs.PktStateMap.Put(&key, states); err != nil {
		t.Fatalf("pkt_state_map put: %v", err)
	}

	const udpDstPortOffset = 36

	// Run 1: idx=0, base_idx=0 → should output base0 (port 80)
	ret1, out1 := runXdpTx(t, objs.XdpTx, basePkt0)
	if ret1 != xdpTx {
		t.Fatalf("run 1: XDP action %d, want %d", ret1, xdpTx)
	}
	gotPort1 := binary.BigEndian.Uint16(out1[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort1 != 80 {
		t.Errorf("run 1: dst port = %d, want 80", gotPort1)
	}

	// Run 2: idx=1, base_idx=1 → must copy base1 (port 443)
	// Feed output of run 1 (which has base0 content) — base_idx change forces copy
	ret2, out2 := runXdpTx(t, objs.XdpTx, out1)
	if ret2 != xdpTx {
		t.Fatalf("run 2: XDP action %d, want %d", ret2, xdpTx)
	}
	gotPort2 := binary.BigEndian.Uint16(out2[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort2 != 443 {
		t.Errorf("run 2 (base change): dst port = %d, want 443", gotPort2)
	}
}

// setupSingleBase is a helper that sets up BPF maps for a single base packet with checksums.
// Returns numCPUs and the base packet bytes.
func setupSingleBase(t *testing.T, objs *BpfObjects, basePkt []byte, diffEntries []BpfDiffEntry) {
	t.Helper()
	numCPUs := ebpf.MustPossibleCPU()

	csumMeta := []BpfChecksumMeta{
		{CsumOffset: 24, HeaderStart: 14, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 0},
		{CsumOffset: 40, HeaderStart: 34, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 17},
	}

	// Base packet
	base := BpfBasePacket{Len: uint16(len(basePkt)), ChecksumCount: uint8(len(csumMeta))}
	copy(base.Data[:], basePkt)
	bases := make([]BpfBasePacket, numCPUs)
	for i := range bases {
		bases[i] = base
	}
	key := uint32(0)
	if err := objs.BasePacketMap.Put(&key, bases); err != nil {
		t.Fatalf("base_packet_map put: %v", err)
	}

	// Diff entries
	for idx, entry := range diffEntries {
		entries := make([]BpfDiffEntry, numCPUs)
		for i := range entries {
			entries[i] = entry
		}
		k := uint32(idx)
		if err := objs.DiffMap.Put(&k, entries); err != nil {
			t.Fatalf("diff_map put[%d]: %v", idx, err)
		}
	}

	// Checksum meta
	for i, meta := range csumMeta {
		metas := make([]BpfChecksumMeta, numCPUs)
		for j := range metas {
			metas[j] = meta
		}
		k := uint32(i)
		if err := objs.ChecksumMetaMap.Put(&k, metas); err != nil {
			t.Fatalf("checksum_meta_map put[%d]: %v", i, err)
		}
	}

	// Pkt state
	states := make([]BpfPktState, numCPUs)
	for i := range states {
		states[i] = BpfPktState{Count: uint32(len(diffEntries)), Idx: 0, LastBaseIdx: lastBaseIdxSentinel}
	}
	if err := objs.PktStateMap.Put(&key, states); err != nil {
		t.Fatalf("pkt_state_map put: %v", err)
	}
}

// makeDiffEntry creates a BpfDiffEntry that changes UDP dst port.
func makeDiffEntry(basePkt []byte, pktLen uint16, newPort uint16, lenChanged bool) BpfDiffEntry {
	const udpDstPortOffset = 36
	var oldPort, newPortBytes [8]uint8
	oldPort[0] = basePkt[udpDstPortOffset]
	oldPort[1] = basePkt[udpDstPortOffset+1]
	binary.BigEndian.PutUint16(newPortBytes[:], newPort)

	var lc uint8
	if lenChanged {
		lc = 1
	}
	entry := BpfDiffEntry{
		PktLen:     pktLen,
		BaseIdx:    0,
		DiffCount:  1,
		LenChanged: lc,
	}
	entry.Diffs[0].Offset = udpDstPortOffset
	entry.Diffs[0].Size = 2
	entry.Diffs[0].OldValue = oldPort
	entry.Diffs[0].NewValue = newPortBytes
	entry.Diffs[0].AffectsCsum = 0x02 // affects UDP checksum (bit 1), not IPv4 header (bit 0)
	return entry
}

// TestXdpTxCsumCache verifies that checksum caching works: first pass computes,
// subsequent passes use cached values via the fast path (no tail call).
func TestXdpTxCsumCache(t *testing.T) {
	objs := loadWithDiffMap(t, 2)

	basePkt := buildUDPPacketSized(t, 80, 128) // 128B > COPY_CHUNK_SIZE for copy-skip
	entry0 := makeDiffEntry(basePkt, uint16(len(basePkt)), 8080, false)
	entry1 := makeDiffEntry(basePkt, uint16(len(basePkt)), 9090, false)
	setupSingleBase(t, objs, basePkt, []BpfDiffEntry{entry0, entry1})

	const udpDstPortOffset = 36
	expected8080 := buildUDPPacketSized(t, 8080, 128)
	expected9090 := buildUDPPacketSized(t, 9090, 128)

	// Run 1: idx=0, entry 0 (csum_cached=0) → compute + cache
	_, out1 := runXdpTx(t, objs.XdpTx, basePkt)
	verifyChecksums(t, "run 1 (compute)", out1, expected8080)

	// Run 2: idx=1, entry 1 (csum_cached=0) → compute + cache
	_, out2 := runXdpTx(t, objs.XdpTx, out1)
	verifyChecksums(t, "run 2 (compute)", out2, expected9090)

	// Run 3: idx=0, entry 0 (csum_cached=1) → fast path
	_, out3 := runXdpTx(t, objs.XdpTx, out2)
	gotPort3 := binary.BigEndian.Uint16(out3[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort3 != 8080 {
		t.Errorf("run 3 (cached): dst port = %d, want 8080", gotPort3)
	}
	verifyChecksums(t, "run 3 (cached)", out3, expected8080)

	// Run 4: idx=1, entry 1 (csum_cached=1) → fast path
	_, out4 := runXdpTx(t, objs.XdpTx, out3)
	gotPort4 := binary.BigEndian.Uint16(out4[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort4 != 9090 {
		t.Errorf("run 4 (cached): dst port = %d, want 9090", gotPort4)
	}
	verifyChecksums(t, "run 4 (cached)", out4, expected9090)

	// Verify no errors
	key := uint32(0)
	var stats []BpfDatarec
	if err := objs.TxStatsMap.Lookup(&key, &stats); err != nil {
		t.Fatalf("tx_stats_map lookup: %v", err)
	}
	for _, s := range stats {
		if s.DiffErrors != 0 {
			t.Errorf("diff_errors = %d", s.DiffErrors)
		}
		if s.ChecksumErrors != 0 {
			t.Errorf("checksum_errors = %d", s.ChecksumErrors)
		}
	}
}

// TestXdpTxLenChanged verifies checksum correctness when packet length differs from base.
// The first pass uses update_packet_lengths + recalc_checksum, then caches the result.
func TestXdpTxLenChanged(t *testing.T) {
	objs := loadWithDiffMap(t, 1)

	basePkt := buildUDPPacketSized(t, 80, 128) // base is 128B
	targetLen := 192                            // target is 192B (len_changed=1)

	entry := makeDiffEntry(basePkt, uint16(targetLen), 8080, true)
	setupSingleBase(t, objs, basePkt, []BpfDiffEntry{entry})

	expected := buildUDPPacketSized(t, 8080, targetLen)

	// Run 1: len_changed → update_packet_lengths + recalc + cache
	_, out1 := runXdpTxExpectLen(t, objs.XdpTx, basePkt, targetLen)
	if len(out1) != targetLen {
		t.Fatalf("run 1: output len = %d, want %d", len(out1), targetLen)
	}
	verifyChecksums(t, "run 1 (len_changed)", out1, expected)

	// Run 2: csum_cached → fast path (no recomputation)
	_, out2 := runXdpTxExpectLen(t, objs.XdpTx, out1, targetLen)
	verifyChecksums(t, "run 2 (cached after len_changed)", out2, expected)

	// Verify port
	const udpDstPortOffset = 36
	gotPort := binary.BigEndian.Uint16(out2[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort != 8080 {
		t.Errorf("run 2: dst port = %d, want 8080", gotPort)
	}
}

// TestXdpTxMixedBaseWithCsum verifies correct behavior when alternating between
// different base packets, each with their own checksum caching.
func TestXdpTxMixedBaseWithCsum(t *testing.T) {
	objs := loadWithDiffMap(t, 2)
	numCPUs := ebpf.MustPossibleCPU()

	basePkt0 := buildUDPPacketSized(t, 80, 128)
	basePkt1 := buildUDPPacketSized(t, 443, 128)

	csumMeta := []BpfChecksumMeta{
		{CsumOffset: 24, HeaderStart: 14, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 0},
		{CsumOffset: 40, HeaderStart: 34, IpHeaderOffset: 14, IpVersion: 4, IpProtocol: 17},
	}

	// Write two base packets
	for idx, pkt := range [][]byte{basePkt0, basePkt1} {
		base := BpfBasePacket{Len: uint16(len(pkt)), ChecksumCount: 2}
		copy(base.Data[:], pkt)
		bases := make([]BpfBasePacket, numCPUs)
		for i := range bases {
			bases[i] = base
		}
		k := uint32(idx)
		if err := objs.BasePacketMap.Put(&k, bases); err != nil {
			t.Fatalf("base_packet_map put[%d]: %v", idx, err)
		}
	}

	// Checksum meta for both bases (same offsets)
	for baseIdx := 0; baseIdx < 2; baseIdx++ {
		for i, meta := range csumMeta {
			metas := make([]BpfChecksumMeta, numCPUs)
			for j := range metas {
				metas[j] = meta
			}
			k := uint32(baseIdx*4 + i) // MAX_CHECKSUM_ENTRIES=4
			if err := objs.ChecksumMetaMap.Put(&k, metas); err != nil {
				t.Fatalf("checksum_meta_map put: %v", err)
			}
		}
	}

	// Diff entry 0: base_idx=0, port 8080
	// Diff entry 1: base_idx=1, port 9090
	const udpDstPortOffset = 36
	for idx, cfg := range []struct {
		baseIdx uint8
		basePkt []byte
		port    uint16
	}{
		{0, basePkt0, 8080},
		{1, basePkt1, 9090},
	} {
		var oldPort, newPort [8]uint8
		oldPort[0] = cfg.basePkt[udpDstPortOffset]
		oldPort[1] = cfg.basePkt[udpDstPortOffset+1]
		binary.BigEndian.PutUint16(newPort[:], cfg.port)

		entry := BpfDiffEntry{
			PktLen:    uint16(len(cfg.basePkt)),
			BaseIdx:   cfg.baseIdx,
			DiffCount: 1,
		}
		entry.Diffs[0].Offset = udpDstPortOffset
		entry.Diffs[0].Size = 2
		entry.Diffs[0].OldValue = oldPort
		entry.Diffs[0].NewValue = newPort
		entry.Diffs[0].AffectsCsum = 0x02

		entries := make([]BpfDiffEntry, numCPUs)
		for i := range entries {
			entries[i] = entry
		}
		k := uint32(idx)
		if err := objs.DiffMap.Put(&k, entries); err != nil {
			t.Fatalf("diff_map put[%d]: %v", idx, err)
		}
	}

	// Pkt state
	key := uint32(0)
	states := make([]BpfPktState, numCPUs)
	for i := range states {
		states[i] = BpfPktState{Count: 2, Idx: 0, LastBaseIdx: lastBaseIdxSentinel}
	}
	if err := objs.PktStateMap.Put(&key, states); err != nil {
		t.Fatalf("pkt_state_map put: %v", err)
	}

	expected0 := buildUDPPacketSized(t, 8080, 128)
	expected1 := buildUDPPacketSized(t, 9090, 128)

	// Run 1: base 0, port 8080 (compute + cache)
	_, out1 := runXdpTx(t, objs.XdpTx, basePkt0)
	verifyChecksums(t, "run 1 (base0, compute)", out1, expected0)

	// Run 2: base 1, port 9090 (compute + cache, base change forces copy)
	_, out2 := runXdpTx(t, objs.XdpTx, out1)
	verifyChecksums(t, "run 2 (base1, compute)", out2, expected1)

	// Run 3: back to base 0 (cached, base change forces copy)
	_, out3 := runXdpTx(t, objs.XdpTx, out2)
	gotPort3 := binary.BigEndian.Uint16(out3[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort3 != 8080 {
		t.Errorf("run 3: dst port = %d, want 8080", gotPort3)
	}
	verifyChecksums(t, "run 3 (base0, cached)", out3, expected0)

	// Run 4: back to base 1 (cached, base change forces copy)
	_, out4 := runXdpTx(t, objs.XdpTx, out3)
	gotPort4 := binary.BigEndian.Uint16(out4[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort4 != 9090 {
		t.Errorf("run 4: dst port = %d, want 9090", gotPort4)
	}
	verifyChecksums(t, "run 4 (base1, cached)", out4, expected1)
}

// TestXdpTxDiffAffectsIPv4Header verifies correctness when a diff modifies the
// IPv4 header (TTL), which affects the IPv4 header checksum but NOT the UDP checksum.
func TestXdpTxDiffAffectsIPv4Header(t *testing.T) {
	objs := loadWithDiffMap(t, 1)

	basePkt := buildUDPPacketSized(t, 80, 128)

	// TTL is at offset 22 (14 eth + 8)
	const ttlOffset = 22

	// Build diff: change TTL from 64 to 128
	var oldTTL, newTTL [8]uint8
	oldTTL[0] = basePkt[ttlOffset]
	newTTL[0] = 128

	entry := BpfDiffEntry{
		PktLen:    uint16(len(basePkt)),
		BaseIdx:   0,
		DiffCount: 1,
	}
	entry.Diffs[0].Offset = ttlOffset
	entry.Diffs[0].Size = 1
	entry.Diffs[0].OldValue = oldTTL
	entry.Diffs[0].NewValue = newTTL
	// TTL at offset 22 is inside IPv4 header [14,34) → affects IPv4 csum (bit0=1)
	// TTL is NOT in pseudo-header [26,34) and NOT in transport [34,128) → bit1=0
	entry.Diffs[0].AffectsCsum = 0x01

	setupSingleBase(t, objs, basePkt, []BpfDiffEntry{entry})

	// Build expected packet with TTL=128 (gopacket recomputes all checksums)
	expectedFull := buildUDPPacketWithTTL(t, 80, 128, 128)

	// Run 1: compute checksums
	ret1, out1 := runXdpTx(t, objs.XdpTx, basePkt)
	if ret1 != xdpTx {
		t.Fatalf("run 1: XDP action %d, want %d", ret1, xdpTx)
	}
	if out1[ttlOffset] != 128 {
		t.Errorf("run 1: TTL = %d, want 128", out1[ttlOffset])
	}
	verifyChecksums(t, "run 1 (TTL change)", out1, expectedFull)

	// Run 2: cached path
	_, out2 := runXdpTx(t, objs.XdpTx, out1)
	if out2[ttlOffset] != 128 {
		t.Errorf("run 2: TTL = %d, want 128", out2[ttlOffset])
	}
	verifyChecksums(t, "run 2 (TTL cached)", out2, expectedFull)
}

// TestXdpTxRawMode verifies that Raw mode (diff_count=0, no user diffs) works
// correctly with checksum caching. The base packet checksums should be preserved.
func TestXdpTxRawMode(t *testing.T) {
	objs := loadWithDiffMap(t, 1)

	basePkt := buildUDPPacketSized(t, 80, 128)

	// Raw mode: diff_count=0, no diffs
	entry := BpfDiffEntry{
		PktLen:    uint16(len(basePkt)),
		BaseIdx:   0,
		DiffCount: 0,
	}
	setupSingleBase(t, objs, basePkt, []BpfDiffEntry{entry})

	// Run 1: copy base, no diffs, checksum should match base
	ret1, out1 := runXdpTx(t, objs.XdpTx, basePkt)
	if ret1 != xdpTx {
		t.Fatalf("run 1: XDP action %d, want %d", ret1, xdpTx)
	}
	verifyChecksums(t, "run 1 (raw mode)", out1, basePkt)

	// Run 2: should use cached path, output identical
	_, out2 := runXdpTx(t, objs.XdpTx, out1)
	verifyChecksums(t, "run 2 (raw cached)", out2, basePkt)

	// Verify packet data is identical to base (no diffs applied)
	const udpDstPortOffset = 36
	gotPort := binary.BigEndian.Uint16(out2[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort != 80 {
		t.Errorf("raw mode: dst port = %d, want 80", gotPort)
	}
}

// TestXdpTxIMIXCsumCache simulates an IMIX-like workload where entries have
// different packet lengths (len_changed=1) and verifies that checksum caching
// works correctly after the first round-robin cycle.
func TestXdpTxIMIXCsumCache(t *testing.T) {
	objs := loadWithDiffMap(t, 2)

	// Two variants with different lengths (simulating IMIX)
	basePkt := buildUDPPacketSized(t, 80, 128) // base is 128B

	// Entry 0: port 8080, target 128B (same as base, len_changed=0)
	entry0 := makeDiffEntry(basePkt, 128, 8080, false)
	// Entry 1: port 9090, target 192B (different from base, len_changed=1)
	entry1 := makeDiffEntry(basePkt, 192, 9090, true)

	setupSingleBase(t, objs, basePkt, []BpfDiffEntry{entry0, entry1})

	const udpDstPortOffset = 36
	expected0 := buildUDPPacketSized(t, 8080, 128)
	expected1 := buildUDPPacketSized(t, 9090, 192)

	// === First cycle: compute + cache ===
	// Run 1: entry 0 (128B, no len change)
	_, out1 := runXdpTx(t, objs.XdpTx, basePkt)
	verifyChecksums(t, "run 1 (128B, compute)", out1, expected0)

	// Run 2: entry 1 (192B, len_changed)
	_, out2 := runXdpTxExpectLen(t, objs.XdpTx, out1, 192)
	verifyChecksums(t, "run 2 (192B, len_changed, compute)", out2, expected1)

	// === Second cycle: should use cached path ===
	// Run 3: entry 0 (128B, cached)
	_, out3 := runXdpTxExpectLen(t, objs.XdpTx, out2, 128)
	gotPort3 := binary.BigEndian.Uint16(out3[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort3 != 8080 {
		t.Errorf("run 3: dst port = %d, want 8080", gotPort3)
	}
	verifyChecksums(t, "run 3 (128B, cached)", out3, expected0)

	// Run 4: entry 1 (192B, cached)
	_, out4 := runXdpTxExpectLen(t, objs.XdpTx, out3, 192)
	gotPort4 := binary.BigEndian.Uint16(out4[udpDstPortOffset : udpDstPortOffset+2])
	if gotPort4 != 9090 {
		t.Errorf("run 4: dst port = %d, want 9090", gotPort4)
	}
	verifyChecksums(t, "run 4 (192B, len_changed, cached)", out4, expected1)

	// Verify no errors
	key := uint32(0)
	var stats []BpfDatarec
	if err := objs.TxStatsMap.Lookup(&key, &stats); err != nil {
		t.Fatalf("tx_stats_map lookup: %v", err)
	}
	for _, s := range stats {
		if s.DiffErrors != 0 {
			t.Errorf("diff_errors = %d", s.DiffErrors)
		}
		if s.ChecksumErrors != 0 {
			t.Errorf("checksum_errors = %d", s.ChecksumErrors)
		}
	}
}
