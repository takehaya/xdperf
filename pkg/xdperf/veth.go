package xdperf

import (
	"path/filepath"

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
func warnVethQueues(logger *zap.Logger, dev string, workers int) {
	link, err := netlink.LinkByName(dev)
	if err != nil || link.Type() != "veth" {
		return
	}
	// IFLA_NUM_RX_QUEUES is the allocated maximum (nr_cpu_ids for a default
	// veth); the queues in use are the rx-* entries in sysfs.
	rx, _ := filepath.Glob(filepath.Join("/sys/class/net", dev, "queues", "rx-*"))
	queues := len(rx)
	if queues <= 0 || workers <= queues {
		return
	}
	logger.Warn("more TX workers than veth queues: workers sharing a peer xdp_ring will drop frames; create the pair with numtxqueues/numrxqueues >= workers",
		zap.String("device", dev), zap.Int("workers", workers), zap.Int("queues", queues))
}
