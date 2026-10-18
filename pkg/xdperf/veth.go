package xdperf

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// warnVethQueues warns when more TX workers than receive queues send on a
// veth. Live-frame TX lands in the peer's xdp_ring picked by the sending CPU
// (cpu % peer rx queues), and each ring holds 256 frames, so workers that
// share a ring overflow it: the frames are dropped (tx_queue_N_xdp_xmit_errors
// in ethtool -S) and TCP turns the drops into retransmissions. The peer may
// live in another netns, so the device's own rx queue count stands in for it
// (veth pairs are normally created with the same count on both ends).
// At low rates the peer's NAPI keeps up and nothing is dropped, so this is a
// warning, not an error.
func warnVethQueues(logger *zap.Logger, dev string, workers int) {
	queues, ok := vethRxQueues(dev)
	if !ok || queues <= 0 || workers <= queues {
		return
	}
	logger.Warn("more TX workers than veth queues: workers sharing a peer xdp_ring may overflow it and drop frames at high rates; create the pair with numtxqueues/numrxqueues >= workers, or raise the queues in use with ethtool -L",
		zap.String("device", dev), zap.Int("workers", workers), zap.Int("queues", queues))
}

// vethRxQueues returns the number of rx queues in use on dev and whether dev
// is a veth. IFLA_NUM_RX_QUEUES is the allocated maximum (nr_cpu_ids for a
// default veth); the queues in use are the rx-* entries in sysfs.
func vethRxQueues(dev string) (int, bool) {
	link, err := netlink.LinkByName(dev)
	if err != nil || link.Type() != "veth" {
		return 0, false
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", dev, "queues"))
	if err != nil {
		return 0, true
	}
	queues := 0
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "rx-") {
			queues++
		}
	}
	return queues, true
}
