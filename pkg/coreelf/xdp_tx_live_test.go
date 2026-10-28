package coreelf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Verify actual veth frames: BPF_PROG_RUN's returned buffer alone cannot
// detect stale xdp_frame lengths when live pages are recycled.
func TestXdpTxLiveFrames(t *testing.T) {
	objs := loadWithDiffMap(t, 2)
	name := fmt.Sprintf("xd64b%d", os.Getpid())
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	tx, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := netlink.LinkByName(name + "p")
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range []netlink.Link{tx, rx} {
		if err := netlink.LinkSetUp(dev); err != nil {
			t.Fatal(err)
		}
		attachment, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpPassDummy, Interface: dev.Attrs().Index})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = attachment.Close() })
	}

	for _, tt := range []struct {
		name    string
		initial int
		sizes   []int
	}{
		{"64B", 64, []int{64}},
		{"1500B", 1500, []int{1500}},
		{"variable", 1500, []int{64, 1500}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := buildUDPPacketSized(t, 5678, 1500)
			entries := make([]BpfDiffEntry, len(tt.sizes))
			want := make([][]byte, len(tt.sizes))
			for i, size := range tt.sizes {
				entries[i] = makeDiffEntry(base, uint16(size), 8080, size != len(base))
				want[i] = buildUDPPacketSized(t, 8080, size)
			}
			setupSingleBase(t, objs, base, entries)
			protocol := binary.NativeEndian.Uint16([]byte{0x08, 0x00})
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(protocol))
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: rx.Attrs().Index, Protocol: protocol}); err != nil {
				t.Fatal(err)
			}
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
				t.Fatal(err)
			}
			// Multiple batches exercise both first-pass checksums and cached diffs.
			const packets = 32
			_, err = objs.XdpTx.Run(&ebpf.RunOptions{
				Data: make([]byte, tt.initial), Repeat: packets, BatchSize: 16,
				Flags:   unix.BPF_F_TEST_XDP_LIVE_FRAMES,
				Context: XdpMd{DataEnd: uint32(tt.initial), IngressIfindex: uint32(tx.Attrs().Index)},
			})
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2048)
			for i := 0; i < packets; i++ {
				n, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil {
					t.Fatalf("packet %d: %v", i, err)
				}
				if expected := want[i%len(want)]; !bytes.Equal(buf[:n], expected) {
					t.Fatalf("packet %d: got %d bytes, want %d; payload, length, port or checksum differs", i, n, len(expected))
				}
			}
		})
	}
}
