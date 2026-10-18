package xdperf

import (
	"fmt"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestWarnVethQueues(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a veth pair")
	}
	name := fmt.Sprintf("xdpmq%d", os.Getpid()%100000)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name, NumTxQueues: 2, NumRxQueues: 2},
		PeerName:  name + "p",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	if q, ok := vethRxQueues(name); !ok || q != 2 {
		t.Fatalf("vethRxQueues(%s) = %d, %v; want 2, true", name, q, ok)
	}
	if _, ok := vethRxQueues("lo"); ok {
		t.Fatal("lo must not be treated as a veth")
	}

	for _, tc := range []struct {
		dev     string
		workers int
		warn    bool
	}{
		{name, 2, false},
		{name, 3, true},
		{"lo", 8, false},
	} {
		core, logs := observer.New(zap.WarnLevel)
		warnVethQueues(zap.New(core), tc.dev, tc.workers)
		if got := logs.Len() > 0; got != tc.warn {
			t.Errorf("%s with %d workers: warned=%v, want %v", tc.dev, tc.workers, got, tc.warn)
		}
	}
}
