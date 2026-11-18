package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestAttachNetkitFastpathValidation(t *testing.T) {
	for _, spec := range []string{
		"",
		"eth0:nk0",
		"no-such-dev:nk0:10.0.0.2",
	} {
		if err := attachNetkitFastpath(spec); err == nil {
			t.Fatalf("attachNetkitFastpath(%q) unexpectedly succeeded", spec)
		}
	}
}

func TestAttachNetkitFastpath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create veth/netkit interfaces and attach BPF programs")
	}

	pid := os.Getpid() % 100000
	vname := fmt.Sprintf("xdpvin%d", pid)
	nkname := fmt.Sprintf("xdpnk%d", pid)
	nkpeer := nkname + "p"

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vname, NumTxQueues: 1, NumRxQueues: 1},
		PeerName:  vname + "p",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	if err := exec.Command("ip", "link", "add", nkname, "type", "netkit", "mode", "l3", "peer", nkpeer).Run(); err != nil {
		t.Skipf("netkit not available: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", nkname).Run() })

	if err := attachNetkitFastpath(vname + ":" + nkname + ":not-an-ip"); err == nil || !strings.Contains(err.Error(), "invalid IPv4") {
		t.Fatalf("expected invalid IPv4 error, got: %v", err)
	}

	// Include an IP whose final octet is >= 128 (bit 31 set in little-endian
	// uint32) to verify 32-bit immediate comparison does not sign-extend.
	for _, podIP := range []string{"10.200.3.2", "10.200.3.200"} {
		spec := fmt.Sprintf("%s:%s:%s", vname, nkname, podIP)
		if err := attachNetkitFastpath(spec); err != nil {
			t.Fatalf("attachNetkitFastpath(%q): %v", spec, err)
		}

		// Verify tcx_to_netkit matches podIP (even when last octet >= 128) and
		// does not take the TC_ACT_OK (0) pass branch.
		pkt := make([]byte, 34)
		pkt[12], pkt[13] = 0x08, 0x00 // ETH_P_IP
		copy(pkt[30:34], net.ParseIP(podIP).To4())
		ret, _, err := nkFastpathProgs[0].Test(pkt)
		if err != nil {
			detachNetkitFastpath()
			t.Fatalf("test tcx_to_netkit for %s: %v", podIP, err)
		}
		if ret == 0 {
			detachNetkitFastpath()
			t.Fatalf("tcx_to_netkit returned TC_ACT_OK (0) for matching Pod IP %s", podIP)
		}
		detachNetkitFastpath()
	}
}
