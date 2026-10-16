package xdperf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"golang.org/x/text/message"
)

// tcpSrvState mirrors enum tcp_srv_state in src/xdp_tcp_server.h.
const (
	tcpSrvSynRcvd     uint8 = 1
	tcpSrvEstablished uint8 = 2
	tcpSrvLastAck     uint8 = 3
)

// tcpServerSweep holds what the control-plane sweeper removed from the flow
// table: the data plane has no timers, so entries whose last packet was lost
// are retired here (see sweepTCPServerFlows).
type tcpServerSweep struct {
	closedImplicit atomic.Uint64 // LAST_ACK entries whose final ACK never came
	synTimeouts    atomic.Uint64 // SYN_RCVD entries that never completed
}

// TCP responder (--tcp-server): see docs/ja/design_xdp_tcp.md section 12.
// The data plane is xdp_rx_tcp_server (src/xdp_tcp_server.h), attached to
// --device; this file resolves the listen address, fills tcp_srv_cfg_map and
// reports the statistics. There are no workers: everything is driven by the
// NIC's receive path.

// tcpListen is the resolved listen endpoint of a --tcp-server run.
type tcpListen struct {
	ipVersion uint8
	ip        net.IP // unspecified when any == true
	any       bool
	port      uint16
	mss       uint16
}

// ParseTCPListen splits "[ip]:port". An empty host means any IPv4 address,
// "::" (written "[::]:port") any IPv6 address.
func ParseTCPListen(s string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, 0, fmt.Errorf("port must be in 1..65535: %q", portStr)
	}
	if host == "" {
		return net.IPv4zero.To4(), uint16(port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("not an IP address: %q", host)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, uint16(port), nil
	}
	return ip, uint16(port), nil
}

func (x *Xdperf) resolveTCPListen() (*tcpListen, error) {
	ip, port, err := ParseTCPListen(x.cfg.TCPListen)
	if err != nil {
		return nil, err
	}
	l := &tcpListen{ip: ip, port: port, any: ip.IsUnspecified()}
	family := netlink.FAMILY_V6
	if ip.To4() != nil {
		l.ipVersion = 4
		family = netlink.FAMILY_V4
	} else {
		l.ipVersion = 6
	}

	// The MSS we advertise is what we can receive: bounded by the device MTU.
	maxMSS := x.Device.MTU - tcpHeaderLen - 20
	if l.ipVersion == 6 {
		maxMSS = x.Device.MTU - tcpHeaderLen - 40
	}
	mss := x.cfg.TCPMSS
	if mss == 0 {
		mss = tcpDefaultMSSv4
		if l.ipVersion == 6 {
			mss = tcpDefaultMSSv6
		}
		if x.cfg.TCPVlanID != 0 {
			mss -= 4 // keep the tagged frame at MTU+14, like the client side
		}
		if mss > maxMSS {
			mss = maxMSS
		}
	} else if mss > maxMSS {
		x.Logger.Warn("advertised MSS exceeds what the device MTU can receive",
			zap.Int("mss", mss), zap.Int("mtu", x.Device.MTU))
	}
	if mss < 1 {
		return nil, fmt.Errorf("device MTU %d too small for TCP", x.Device.MTU)
	}
	l.mss = uint16(mss)

	// The kernel must answer ARP/NDP for the listen address, so it should be
	// configured on the device (or its VLAN sub-interface). Warn, don't fail:
	// a sub-interface with another name is a legitimate setup.
	if !l.any {
		if link, err := netlink.LinkByName(x.Device.Name); err == nil {
			found := false
			if addrs, err := netlink.AddrList(link, family); err == nil {
				for _, a := range addrs {
					if a.IP.Equal(ip) {
						found = true
						break
					}
				}
			}
			if !found && x.cfg.TCPVlanID != 0 {
				if links, err := netlink.LinkList(); err == nil {
					for _, cand := range links {
						if v, ok := cand.(*netlink.Vlan); ok && v.VlanId == x.cfg.TCPVlanID && v.ParentIndex == link.Attrs().Index {
							if addrs, err := netlink.AddrList(cand, family); err == nil {
								for _, a := range addrs {
									if a.IP.Equal(ip) {
										found = true
									}
								}
							}
						}
					}
				}
			}
			if !found {
				x.Logger.Warn("listen address is not configured on the device; ARP/NDP for it will go unanswered",
					zap.String("ip", ip.String()), zap.String("device", x.Device.Name))
			}
		}
	}
	return l, nil
}

func (x *Xdperf) initTCPServerMaps(l *tcpListen) error {
	cfg := coreelf.BpfTcpSrvCfg{
		ListenPort: l.port,
		VlanId:     uint16(x.cfg.TCPVlanID),
		VlanPcp:    uint8(x.cfg.TCPVlanPCP),
		IpVersion:  l.ipVersion,
		AckEvery:   uint8(x.cfg.TCPAckEvery),
		Mss:        l.mss,
		ListenIp:   ipTo4Words(l.ip),
	}
	if l.any {
		cfg.AnyAddr = 1
	}
	zero := uint32(0)
	if err := x.bpfobjs.TcpSrvCfgMap.Put(&zero, &cfg); err != nil {
		return fmt.Errorf("tcp_srv_cfg_map: %w", err)
	}
	return nil
}

// readTCPServerStats sums tcp_srv_stats_map over all CPUs.
func (x *Xdperf) readTCPServerStats(recs []coreelf.BpfTcpSrvStats) (coreelf.BpfTcpSrvStats, error) {
	var zero uint32
	if err := x.bpfobjs.TcpSrvStatsMap.Lookup(&zero, &recs); err != nil {
		return coreelf.BpfTcpSrvStats{}, err
	}
	return sumPerCPU(recs), nil
}

// tcpServerSweepAfter is the age (since the last packet) after which the
// sweeper retires a LAST_ACK / SYN_RCVD entry. It must exceed the longest gap
// between two retransmissions of the peer's FIN or SYN (rto << 6 for the XDP
// client, similar for Linux), otherwise a live flow would be swept and its
// next retransmission answered with RST.
func (x *Xdperf) tcpServerSweepAfter() time.Duration {
	if x.cfg.TCPSweepAfter > 0 {
		return x.cfg.TCPSweepAfter
	}
	d := 65 * x.cfg.TCPRTO
	if d < 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

// tcpServerActive is the number of accepted flows that have not ended. An
// entry silently evicted by the LRU (table full, see table_full) is not seen
// and stays counted.
func tcpServerActive(s coreelf.BpfTcpSrvStats, sw *tcpServerSweep) uint64 {
	gone := s.Closed + s.ResetEst + s.RecycledEst + sw.closedImplicit.Load()
	if s.Accepted < gone {
		return 0
	}
	return s.Accepted - gone
}

func monotonicNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

// sweepTCPServerFlows walks the flow table once and retires entries the data
// plane can never finish by itself: a LAST_ACK flow whose final ACK was lost
// (the peer is done, so it counts as closed) and a SYN_RCVD flow whose
// handshake never completed. stale is the age (in ns since the entry's last
// packet) beyond which an entry is retired (0 = every such entry, used at
// shutdown when nothing more will arrive).
//
// The data plane keeps running meanwhile, so an entry is deleted only if a
// fresh lookup still shows the snapshotted state, ISN and timestamp (a new SYN
// from the same peer recreates the entry with a new ISN), and it is counted
// only when the delete itself succeeds (the data plane may have closed it
// first). A packet arriving between that lookup and the delete can still be
// lost; the window is two syscalls wide and only affects entries that have
// been idle for the whole sweep threshold.
func (x *Xdperf) sweepTCPServerFlows(sw *tcpServerSweep, stale uint64) error {
	now, err := monotonicNow()
	if err != nil {
		return err
	}
	m := x.bpfobjs.TcpSrvFlowMap
	type victim struct {
		key coreelf.BpfTcpSrvKey
		val coreelf.BpfTcpSrvFlow
	}
	var victims []victim
	consider := func(k coreelf.BpfTcpSrvKey, v coreelf.BpfTcpSrvFlow) {
		if v.State != tcpSrvLastAck && v.State != tcpSrvSynRcvd {
			return
		}
		if stale > 0 && (now < v.LastNs || now-v.LastNs < stale) {
			return
		}
		victims = append(victims, victim{k, v})
	}

	const chunk = 4096
	keys := make([]coreelf.BpfTcpSrvKey, chunk)
	vals := make([]coreelf.BpfTcpSrvFlow, chunk)
	var cursor ebpf.MapBatchCursor
	batched := true
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			consider(keys[i], vals[i])
		}
		if err == nil {
			continue
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EINVAL) {
			batched = false
			victims = victims[:0]
			break
		}
		return err
	}
	if !batched {
		// Kernels without batch lookup: one syscall pair per entry.
		var k coreelf.BpfTcpSrvKey
		var v coreelf.BpfTcpSrvFlow
		it := m.Iterate()
		for it.Next(&k, &v) {
			consider(k, v)
		}
		if err := it.Err(); err != nil {
			return err
		}
	}
	for i := range victims {
		vc := &victims[i]
		var cur coreelf.BpfTcpSrvFlow
		if err := m.Lookup(&vc.key, &cur); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return err
		}
		if cur.State != vc.val.State || cur.Iss != vc.val.Iss || cur.LastNs != vc.val.LastNs {
			continue // the flow moved on (new packet or recycled by a new SYN)
		}
		if err := m.Delete(&vc.key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return err
		}
		switch cur.State {
		case tcpSrvLastAck:
			sw.closedImplicit.Add(1)
		case tcpSrvSynRcvd:
			sw.synTimeouts.Add(1)
		}
	}
	return nil
}

func (x *Xdperf) runTCPServerSweeper(ctx context.Context, sw *tcpServerSweep, stale time.Duration, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := x.sweepTCPServerFlows(sw, uint64(stale.Nanoseconds())); err != nil {
				x.Logger.Warn("tcp server flow sweep failed", zap.Error(err))
			}
		}
	}
}

func (x *Xdperf) showTCPServerStats(ctx context.Context, sw *tcpServerSweep) {
	recs := make([]coreelf.BpfTcpSrvStats, ebpf.MustPossibleCPU())
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prev coreelf.BpfTcpSrvStats
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, err := x.readTCPServerStats(recs)
			if err != nil {
				x.Logger.Warn("failed to read tcp server stats", zap.Error(err))
				continue
			}
			gbps := float64(safeDelta(cur.BytesRcvd, prev.BytesRcvd)*8) / 1e9
			p.Printf("tcp-server: active %d accepted %d closed %d | %.3f Gbps rcvd, %d segs/s, %d acks/s, ooo %d/s, rst %d/s\n",
				tcpServerActive(cur, sw), cur.Accepted, cur.Closed+sw.closedImplicit.Load(), gbps,
				safeDelta(cur.DataSegs, prev.DataSegs), safeDelta(cur.AcksSent, prev.AcksSent),
				safeDelta(cur.OutOfOrder, prev.OutOfOrder), safeDelta(cur.RstRcvd, prev.RstRcvd))
			prev = cur
		}
	}
}

// runTCPServer is the entry point of --tcp-server mode.
func (x *Xdperf) runTCPServer(ctx context.Context) error {
	l, err := x.resolveTCPListen()
	if err != nil {
		return err
	}
	if err := x.initTCPServerMaps(l); err != nil {
		return fmt.Errorf("failed to init TCP server maps: %w", err)
	}
	x.Logger.Info("TCP responder configured",
		zap.Uint8("ip_version", l.ipVersion),
		zap.String("listen", net.JoinHostPort(l.ip.String(), fmt.Sprint(l.port))),
		zap.Bool("any_addr", l.any),
		zap.Uint16("mss", l.mss),
		zap.Int("vlan_id", x.cfg.TCPVlanID),
		zap.Int("ack_every", x.cfg.TCPAckEvery),
		zap.Int("max_conns", x.cfg.TCPMaxConns),
		zap.Duration("sweep_after", x.tcpServerSweepAfter()),
	)

	link, err := x.attachXDP(x.bpfobjs.XdpRxTcpServer, x.Device)
	if err != nil {
		return err
	}
	// Detached explicitly before the final sweep and statistics (below);
	// the deferred call only covers early returns. Close is idempotent.
	detach := func() {
		x.Logger.Info("detaching XDP program")
		if err := link.Close(); err != nil {
			x.Logger.Warn("failed to detach XDP program", zap.Error(err))
		}
	}
	detached := false
	defer func() {
		if !detached {
			detach()
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sw := &tcpServerSweep{}
	go x.showTCPServerStats(ctx, sw)
	sweeperDone := make(chan struct{})
	go x.runTCPServerSweeper(ctx, sw, x.tcpServerSweepAfter(), sweeperDone)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	var durationCh <-chan time.Time
	if x.cfg.Duration > 0 {
		durationCh = time.After(x.cfg.Duration)
	}
	x.Logger.Info("TCP responder started", zap.String("device", x.Device.Name))
	select {
	case <-durationCh:
		x.Logger.Info("duration elapsed, shutting down TCP responder")
	case s := <-sig:
		x.Logger.Info("received signal, shutting down TCP responder", zap.String("signal", s.String()))
	case <-ctx.Done():
	}
	cancel()
	<-sweeperDone // never run two sweeps at once (double counting)

	// Stop answering first: otherwise the final sweep below could delete a
	// flow that is still in use (its next retransmission would get a stray
	// RST) and the statistics would miss what arrives after they are read.
	detach()
	detached = true

	// One last sweep, regardless of age: nothing more will be answered, so a
	// LAST_ACK flow (final ACK lost) is closed and a SYN_RCVD one timed out.
	if err := x.sweepTCPServerFlows(sw, 0); err != nil {
		x.Logger.Warn("tcp server flow sweep failed", zap.Error(err))
	}
	recs := make([]coreelf.BpfTcpSrvStats, ebpf.MustPossibleCPU())
	s, err := x.readTCPServerStats(recs)
	if err != nil {
		x.Logger.Error("failed to read tcp server stats", zap.Error(err))
		return nil
	}
	// Field names accepted / closed / bytes match the xdperf-sink JSON so the
	// two receivers can be compared with the same scripts.
	x.Logger.Info("tcp server final statistics",
		zap.Uint64("syn_rcvd", s.SynRcvd),
		zap.Uint64("synack_sent", s.SynackSent),
		zap.Uint64("accepted", s.Accepted),
		zap.Uint64("closed", s.Closed+sw.closedImplicit.Load()),
		zap.Uint64("closed_implicit", sw.closedImplicit.Load()),
		zap.Uint64("syn_timeouts", sw.synTimeouts.Load()),
		zap.Uint64("active", tcpServerActive(s, sw)),
		zap.Uint64("bytes", s.BytesRcvd),
		zap.Uint64("data_segments", s.DataSegs),
		zap.Uint64("acks_sent", s.AcksSent),
		zap.Uint64("dup_acks_sent", s.DupAcksSent),
		zap.Uint64("out_of_order", s.OutOfOrder),
		zap.Uint64("fin_rcvd", s.FinRcvd),
		zap.Uint64("fin_sent", s.FinSent),
		zap.Uint64("rst_rcvd", s.RstRcvd),
		zap.Uint64("recycled", s.Recycled),
		zap.Uint64("recycled_established", s.RecycledEst),
		zap.Uint64("table_full", s.TableFull),
		zap.Uint64("stray", s.Stray),
		zap.Uint64("rst_sent", s.RstSent),
		zap.Uint64("reset_established", s.ResetEst),
		zap.Uint64("unexpected", s.Unexpected),
		zap.Uint64("bad_length", s.BadLen),
		zap.Uint64("build_errors", s.BuildErrors),
	)
	return nil
}
