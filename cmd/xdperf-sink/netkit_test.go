package main

import (
	"fmt"
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

	spec := fmt.Sprintf("%s:%s:10.200.3.2", vname, nkname)
	if err := attachNetkitFastpath(spec); err != nil {
		t.Fatalf("attachNetkitFastpath(%q): %v", spec, err)
	}
	detachNetkitFastpath()
}
