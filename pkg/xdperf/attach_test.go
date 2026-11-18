package xdperf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestCheckLiveFrameTXSupport(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network interfaces and query netdev XDP features")
	}

	t.Run("loopback rejected", func(t *testing.T) {
		lo, err := net.InterfaceByName("lo")
		if err != nil {
			t.Fatalf("get lo: %v", err)
		}
		err = checkLiveFrameTXSupport(lo)
		if err == nil {
			t.Fatal("expected loopback to be rejected for live-frame TX")
		}
		if !strings.Contains(err.Error(), "ndo_xdp_xmit") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("veth accepted", func(t *testing.T) {
		name := fmt.Sprintf("xdptx%d", os.Getpid()%100000)
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: name, NumTxQueues: 1, NumRxQueues: 1},
			PeerName:  name + "p",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatalf("create veth: %v", err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(veth) })

		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatalf("get veth %s: %v", name, err)
		}
		if err := checkLiveFrameTXSupport(iface); err != nil {
			t.Fatalf("expected veth to be accepted, got: %v", err)
		}
	})

	t.Run("netkit rejected with guidance", func(t *testing.T) {
		name := fmt.Sprintf("xdpnk%d", os.Getpid()%100000)
		peer := name + "p"
		if err := exec.Command("ip", "link", "add", name, "type", "netkit", "mode", "l2", "peer", peer).Run(); err != nil {
			t.Skipf("netkit not available: %v", err)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })

		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatalf("get netkit %s: %v", name, err)
		}
		err = checkLiveFrameTXSupport(iface)
		if err == nil {
			t.Fatal("expected netkit to be rejected for live-frame TX")
		}
		if !strings.Contains(err.Error(), "(netkit)") || !strings.Contains(err.Error(), "ndo_xdp_xmit") {
			t.Fatalf("expected netkit-specific guidance, got: %v", err)
		}
	})
}
