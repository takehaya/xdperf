package xdperf

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/plugin"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"golang.org/x/text/message"
)

// TCP stream mode: see docs/ja/design_xdp_tcp.md. The data plane is
// xdp_tx_tcp (driven by bpf_prog_run live frames) and xdp_rx_tcp (attached to
// the device); this file builds the frame template, fills the maps, drives the
// workers and reports the statistics.

const (
	tcpHeaderLen = 20
	tcpSynOptLen = 8 // MSS + NOP + window scale on SYN (TCP_SYN_OPT_LEN)
	// tcpMinMSS keeps every data frame at or above the 60-byte Ethernet
	// minimum (no padding to account for) and above the SYN option length.
	tcpMinMSS        = 64
	tcpDefaultMSSv4  = 1448
	tcpDefaultMSSv6  = 1428
	tcpTxRepeatBurst = 1 << 16 // bpf_prog_run repeat count when not rate limited

	// Retry limits written to tcp_cfg. SYN/FIN back off exponentially
	// (rto << n), so 6 retries span rto * (1+2+...+64) = 127 rto.
	tcpMaxSynRetries  = 6
	tcpMaxFinRetries  = 6
	tcpMaxDataRetries = 8
	// tcpBackoffSpan is how long the longest retry sequence (FIN, or the ACK
	// probes of FIN_WAIT_2) can take, in units of rto.
	tcpBackoffSpan = 127
	// tcpAbortGrace bounds how long the workers keep running after abort so
	// that every open flow gets its RST out.
	tcpAbortGrace = 500 * time.Millisecond
)

// tcpFlowState mirrors enum tcp_flow_state in src/xdp_tcp.h.
const (
	tcpFlowClosed uint8 = iota
	tcpFlowSynSent
	tcpFlowEstablished
	tcpFlowFinWait1
	tcpFlowFinWait2
	tcpFlowDone
	tcpFlowFailed
	tcpFlowSkipped
)

// tcpTarget is the resolved L2/L3 endpoint of a TCP stream run.
type tcpTarget struct {
	ipVersion uint8
	srcIP     net.IP
	dstIP     net.IP
	dstPort   uint16
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	vlanID    uint16
	vlanPCP   uint8
	l3Off     uint16
	l4Off     uint16
	hdrLen    uint16
	mss       uint16
}

// resolveTCPTarget parses --tcp-dst, picks the source address and resolves the
// next-hop MAC through the kernel's routing table and neighbor cache.
func (x *Xdperf) resolveTCPTarget() (*tcpTarget, error) {
	host, portStr, err := net.SplitHostPort(x.cfg.TCPDst)
	if err != nil {
		return nil, fmt.Errorf("invalid --tcp-dst %q: %w", x.cfg.TCPDst, err)
	}
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid --tcp-dst host %q", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid --tcp-dst port %q", portStr)
	}

	t := &tcpTarget{dstIP: dstIP, dstPort: uint16(port), srcMAC: x.Device.HardwareAddr}
	if v4 := dstIP.To4(); v4 != nil {
		t.ipVersion = 4
		t.dstIP = v4
	} else {
		t.ipVersion = 6
	}

	// Routing lookup: egress link, gateway and preferred source address.
	routes, err := netlink.RouteGet(dstIP)
	if err != nil || len(routes) == 0 {
		return nil, fmt.Errorf("no route to %s: %v", dstIP, err)
	}
	route := routes[0]
	nextHop := dstIP
	if route.Gw != nil {
		nextHop = route.Gw
	}
	if x.cfg.TCPSrcIP != "" {
		t.srcIP = net.ParseIP(x.cfg.TCPSrcIP)
		if t.srcIP == nil {
			return nil, fmt.Errorf("invalid --tcp-src-ip %q", x.cfg.TCPSrcIP)
		}
	} else {
		t.srcIP = route.Src
	}
	if t.srcIP == nil {
		return nil, fmt.Errorf("could not determine a source address for %s; pass --tcp-src-ip", dstIP)
	}
	if t.ipVersion == 4 {
		if t.srcIP.To4() == nil {
			return nil, fmt.Errorf("--tcp-src-ip %s is not IPv4 but --tcp-dst is", t.srcIP)
		}
		t.srcIP = t.srcIP.To4()
	} else if t.srcIP.To4() != nil {
		return nil, fmt.Errorf("--tcp-src-ip %s is not IPv6 but --tcp-dst is", t.srcIP)
	}

	egress, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("route egress link %d: %w", route.LinkIndex, err)
	}
	egressName := egress.Attrs().Name
	if route.LinkIndex != x.Device.Index {
		// A VLAN sub-interface of --device is the expected case when tagging;
		// Preserve the legacy CLI warning, but reject mismatched plugin routes.
		parent := egress.Attrs().ParentIndex
		if _, isVlan := egress.(*netlink.Vlan); !isVlan || parent != x.Device.Index {
			if x.cfg.PluginName != "" {
				return nil, fmt.Errorf("TCP variant route via %s does not use device %s or its VLAN child", egressName, x.Device.Name)
			}
			x.Logger.Warn("route to --tcp-dst leaves through a different interface than --device; frames are still sent on --device",
				zap.String("route_dev", egressName), zap.String("device", x.Device.Name))
		}
	}

	if x.cfg.TCPDstMAC != "" {
		t.dstMAC, err = net.ParseMAC(x.cfg.TCPDstMAC)
		if err != nil {
			return nil, fmt.Errorf("invalid --tcp-dst-mac: %w", err)
		}
	} else {
		macStr := plugin.ResolveNeighborMAC(nextHop.String(), egressName)
		if macStr == "" {
			return nil, fmt.Errorf("could not resolve the MAC address of next hop %s via %s; pass --tcp-dst-mac", nextHop, egressName)
		}
		t.dstMAC, err = net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("neighbor cache returned an invalid MAC %q: %w", macStr, err)
		}
	}

	t.vlanID = uint16(x.cfg.TCPVlanID)
	t.vlanPCP = uint8(x.cfg.TCPVlanPCP)
	t.l3Off = 14
	if t.vlanID != 0 {
		t.l3Off += 4
	}
	if t.ipVersion == 4 {
		t.l4Off = t.l3Off + 20
	} else {
		t.l4Off = t.l3Off + 40
	}
	t.hdrLen = t.l4Off + tcpHeaderLen

	mss := x.cfg.TCPMSS
	if mss == 0 {
		mss = tcpDefaultMSSv4
		if t.ipVersion == 6 {
			mss = tcpDefaultMSSv6
		}
		if t.vlanID != 0 {
			// keep the on-wire frame at MTU+14 regardless of the tag
			mss -= 4
		}
		// a smaller device MTU (overlay, tunnel, IPv6 minimum) caps the default
		if maxMSS := x.Device.MTU - int(t.hdrLen-t.l3Off); mss > maxMSS {
			mss = maxMSS
		}
		if mss < tcpMinMSS {
			return nil, fmt.Errorf("device MTU %d of %s is too small for TCP stream mode", x.Device.MTU, x.Device.Name)
		}
	}
	frameLen := int(t.hdrLen) + mss
	if frameLen > x.getBpfConstant("max_packet_size") {
		return nil, fmt.Errorf("frame length %d (headers %d + mss %d) exceeds the data-plane maximum %d", frameLen, t.hdrLen, mss, x.getBpfConstant("max_packet_size"))
	}
	if ipLen := frameLen - int(t.l3Off); ipLen > x.Device.MTU {
		return nil, fmt.Errorf("IP packet length %d (mss %d) exceeds the MTU %d of %s; lower --tcp-mss", ipLen, mss, x.Device.MTU, x.Device.Name)
	}
	t.mss = uint16(mss)
	return t, nil
}

// buildTCPTemplate serializes the frame the TX program rewrites per segment:
// everything except ports/seq/ack/flags/lengths/checksums is final here.
func buildTCPTemplate(t *tcpTarget, srcPort uint16) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: t.srcMAC, DstMAC: t.dstMAC}
	var ipLayer gopacket.SerializableLayer
	var ipType layers.EthernetType
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(t.dstPort), Window: 65535, DataOffset: 5}
	if t.ipVersion == 4 {
		ipType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: layers.IPProtocolTCP, SrcIP: t.srcIP, DstIP: t.dstIP}
		if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
			return nil, err
		}
		ipLayer = ip4
	} else {
		ipType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: t.srcIP, DstIP: t.dstIP}
		if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
			return nil, err
		}
		ipLayer = ip6
	}
	stack := []gopacket.SerializableLayer{eth}
	if t.vlanID != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{Priority: t.vlanPCP, VLANIdentifier: t.vlanID, Type: ipType})
	} else {
		eth.EthernetType = ipType
	}
	stack = append(stack, ipLayer, tcp, gopacket.Payload(make([]byte, t.mss)))

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		return nil, fmt.Errorf("serialize TCP template: %w", err)
	}
	out := buf.Bytes()
	if len(out) != int(t.hdrLen)+int(t.mss) {
		return nil, fmt.Errorf("template length %d != expected %d", len(out), int(t.hdrLen)+int(t.mss))
	}
	return out, nil
}

// pseudoHeaderAddrSum is the unfolded 16-bit word sum of src+dst addresses,
// the constant part of the TCP pseudo header checksum.
func pseudoHeaderAddrSum(src, dst net.IP) uint32 {
	var sum uint32
	for _, ip := range [][]byte{src, dst} {
		for i := 0; i+1 < len(ip); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[i:]))
		}
	}
	return sum
}

func ipTo4Words(ip net.IP) [4]uint32 {
	var w [4]uint32
	b := []byte(ip)
	for i := 0; i < len(b)/4 && i < 4; i++ {
		// network byte order in memory: NativeEndian read of the raw bytes
		w[i] = binary.NativeEndian.Uint32(b[i*4:])
	}
	return w
}

func (x *Xdperf) initTCPMaps(t *tcpTarget, template []byte) error {
	cfg := coreelf.BpfTcpCfg{
		FlowCount:      uint32(x.cfg.TCPFlows),
		WindowSegs:     uint32(x.cfg.TCPWindow),
		Mss:            t.mss,
		PortBase:       uint16(x.cfg.TCPPortBase),
		DstPort:        t.dstPort,
		HdrLen:         t.hdrLen,
		L3Off:          t.l3Off,
		L4Off:          t.l4Off,
		VlanId:         t.vlanID,
		VlanPcp:        t.vlanPCP,
		IpVersion:      t.ipVersion,
		MaxSynRetries:  tcpMaxSynRetries,
		MaxFinRetries:  tcpMaxFinRetries,
		MaxDataRetries: tcpMaxDataRetries,
		PseudoSum:      pseudoHeaderAddrSum(t.srcIP, t.dstIP),
		SrcIp:          ipTo4Words(t.srcIP),
		DstIp:          ipTo4Words(t.dstIP),
		BytesPerFlow:   x.cfg.TCPBytes,
		RtoNs:          uint64(x.cfg.TCPRTO.Nanoseconds()),
	}
	if x.cfg.TCPIPID == "shared" {
		cfg.IpIdShared = 1
	}
	if int(t.l4Off) > len(cfg.HdrTmpl) || len(template) < int(t.l4Off) {
		return fmt.Errorf("header length %d does not fit the data-plane template (%d)", t.l4Off, len(cfg.HdrTmpl))
	}
	copy(cfg.HdrTmpl[:], template[:t.l4Off])
	zero := uint32(0)
	if err := x.bpfobjs.TcpCfgMap.Put(&zero, &cfg); err != nil {
		return fmt.Errorf("tcp_cfg_map: %w", err)
	}

	flows := x.cfg.TCPFlows
	keys := make([]uint32, flows)
	vals := make([]coreelf.BpfTcpFlow, flows)
	for i := 0; i < flows; i++ {
		keys[i] = uint32(i)
		bytesTarget := x.cfg.TCPBytes
		if x.tcpVariantBytes != nil {
			bytesTarget = x.tcpVariantBytes[i]
		}
		vals[i] = coreelf.BpfTcpFlow{
			State:       tcpFlowClosed,
			SrcPort:     uint16(x.cfg.TCPPortBase + i),
			Iss:         rand.Uint32(),
			BytesTarget: bytesTarget,
		}
	}
	if _, err := x.bpfobjs.TcpFlowMap.BatchUpdate(keys, vals, nil); err != nil {
		// Older kernels without batch ops: fall back to one update per flow.
		x.Logger.Debug("tcp_flow_map batch update unavailable, falling back to per-entry updates", zap.Error(err))
		for i := range keys {
			if err := x.bpfobjs.TcpFlowMap.Put(&keys[i], &vals[i]); err != nil {
				return fmt.Errorf("tcp_flow_map[%d]: %w", i, err)
			}
		}
	}

	// Flow ownership: worker slot k drives flows k, k+P, k+2P, ...
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	states := make([]coreelf.BpfTcpCpuState, numCPU)
	par := len(x.cpus)
	for k, cpu := range x.cpus {
		if cpu < 0 || cpu >= numCPU {
			return fmt.Errorf("worker cpu %d out of range", cpu)
		}
		count := 0
		if flows > k {
			count = (flows - k + par - 1) / par
		}
		states[cpu] = coreelf.BpfTcpCpuState{First: uint32(k), Stride: uint32(par), Count: uint32(count)}
	}
	if err := x.bpfobjs.TcpCpuStateMap.Put(&zero, states); err != nil {
		return fmt.Errorf("tcp_cpu_state_map: %w", err)
	}
	return nil
}

// warnEphemeralPortOverlap warns when the flows' source ports fall inside the
// kernel's ephemeral port range: xdp_rx_tcp would then also capture replies
// to the host's own connections to the same destination address and port.
func (x *Xdperf) warnEphemeralPortOverlap() {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return
	}
	var lo, hi int
	if _, err := fmt.Sscan(string(b), &lo, &hi); err != nil {
		return
	}
	first, last := x.cfg.TCPPortBase, x.cfg.TCPPortBase+x.cfg.TCPFlows-1
	if first <= hi && last >= lo {
		x.Logger.Warn("TCP source ports overlap the kernel's ephemeral port range; host connections to the same destination may be captured by xdp_rx_tcp. Move --tcp-port-base or reserve the ports with net.ipv4.ip_local_reserved_ports",
			zap.Int("first_port", first), zap.Int("last_port", last),
			zap.Int("ephemeral_lo", lo), zap.Int("ephemeral_hi", hi))
	}
}

// updateTCPCfg rewrites tcp_cfg with fn applied. TX/RX keep running while
// it is written; only drain/abort change, so a torn read is harmless.
func (x *Xdperf) updateTCPCfg(fn func(*coreelf.BpfTcpCfg)) error {
	zero := uint32(0)
	var cfg coreelf.BpfTcpCfg
	if err := x.bpfobjs.TcpCfgMap.Lookup(&zero, &cfg); err != nil {
		return err
	}
	fn(&cfg)
	return x.bpfobjs.TcpCfgMap.Put(&zero, &cfg)
}

// readTCPStats sums tcp_stats_map over all CPUs.
func (x *Xdperf) readTCPStats(recs []coreelf.BpfTcpStats) (coreelf.BpfTcpStats, error) {
	var zero uint32
	if err := x.bpfobjs.TcpStatsMap.Lookup(&zero, &recs); err != nil {
		return coreelf.BpfTcpStats{}, err
	}
	return sumPerCPU(recs), nil
}

// sumPerCPU adds up every uint64 field of a per-CPU stats struct, so a
// counter added to the BPF struct can never be forgotten in the sum.
func sumPerCPU[T any](recs []T) T {
	var sum T
	sv := reflect.ValueOf(&sum).Elem()
	for i := range recs {
		rv := reflect.ValueOf(&recs[i]).Elem()
		for f := 0; f < sv.NumField(); f++ {
			if fv := sv.Field(f); fv.Kind() == reflect.Uint64 && fv.CanSet() {
				fv.SetUint(fv.Uint() + rv.Field(f).Uint())
			}
		}
	}
	return sum
}

// tcpActiveFlows is the number of established flows not closed yet.
func tcpActiveFlows(s coreelf.BpfTcpStats) uint64 {
	gone := s.Done + s.FailedEst
	if s.Established < gone {
		return 0
	}
	return s.Established - gone
}

func (x *Xdperf) showTCPStats(ctx context.Context) {
	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prev coreelf.BpfTcpStats
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, err := x.readTCPStats(recs)
			if err != nil {
				x.Logger.Warn("failed to read tcp stats", zap.Error(err))
				continue
			}
			gbps := float64(safeDelta(cur.BytesAcked, prev.BytesAcked)*8) / 1e9
			p.Printf("tcp: est %d done %d fail %d | %.3f Gbps acked, %d segs/s, %d acks/s, rtx %d/s, stalls %d/s\n",
				tcpActiveFlows(cur), cur.Done, cur.Failed, gbps,
				safeDelta(cur.DataSegs, prev.DataSegs), safeDelta(cur.AcksRcvd, prev.AcksRcvd),
				safeDelta(cur.RtxSegs, prev.RtxSegs), safeDelta(cur.WindowStalls, prev.WindowStalls))
			prev = cur
		}
	}
}

// tcpWorker drives xdp_tx_tcp on one CPU until ctx is cancelled.
func (x *Xdperf) tcpWorker(ctx context.Context, cpu int, prog *ebpf.Program, runOpts *ebpf.RunOptions, interval time.Duration) error {
	runtime.LockOSThread()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(unix.Gettid(), &cpuset); err != nil {
		return fmt.Errorf("failed to set CPU affinity: %v", err)
	}
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		ret, err := prog.Run(runOpts)
		if err != nil {
			return fmt.Errorf("bpf_prog_run failed: %w", err)
		}
		// In live-frames mode the kernel does not report the program's XDP
		// action; retval is 0 on success (same contract as the replay client).
		if ret != 0 {
			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
		}
		if ticker != nil {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// runTCP is the client entry point of --tcp mode.
func (x *Xdperf) runTCP(ctx context.Context) error {
	t, err := x.resolveTCPTarget()
	if err != nil {
		return err
	}
	template, err := buildTCPTemplate(t, uint16(x.cfg.TCPPortBase))
	if err != nil {
		return err
	}
	if err := x.initTCPMaps(t, template); err != nil {
		return fmt.Errorf("failed to init TCP maps: %w", err)
	}

	x.Logger.Info("TCP stream target resolved",
		zap.Uint8("ip_version", t.ipVersion),
		zap.String("src", t.srcIP.String()),
		zap.String("dst", net.JoinHostPort(t.dstIP.String(), fmt.Sprint(t.dstPort))),
		zap.String("src_mac", t.srcMAC.String()),
		zap.String("dst_mac", t.dstMAC.String()),
		zap.Uint16("vlan_id", t.vlanID),
		zap.Uint16("mss", t.mss),
		zap.Int("frame_len", len(template)),
		zap.Int("flows", x.cfg.TCPFlows),
		zap.Int("port_base", x.cfg.TCPPortBase),
		zap.Int("window_segs", x.cfg.TCPWindow),
		zap.Uint64("bytes_per_flow", x.cfg.TCPBytes),
		zap.Duration("rto", x.cfg.TCPRTO),
	)

	if x.mixed != nil {
		if err := x.initMixedMaps(); err != nil {
			return err
		}
	}
	x.warnEphemeralPortOverlap()

	// The RX program must be in place before the first SYN leaves.
	rxProg := x.bpfobjs.XdpRxTcp
	if x.mixed != nil {
		rxProg = x.bpfobjs.XdpRxMixed
	}
	lrx, err := x.attachXDP(rxProg, x.Device)
	if err != nil {
		return err
	}
	defer lrx.Close()

	// Rate limiting: --pps caps the number of TX iterations (segments) per second.
	repeat := uint32(tcpTxRepeatBurst)
	var interval time.Duration
	if x.cfg.PPS > 0 {
		// Fractional per-worker rate: with --pps below the worker count each
		// worker runs less than once per second instead of being rounded
		// up to 1 pps (which would exceed the total).
		ppsPerCPU := float64(x.cfg.PPS) / float64(len(x.cpus))
		repeat = uint32(ppsPerCPU / 100) // 10ms batches
		if repeat < 1 {
			repeat = 1
		}
		interval = time.Duration(float64(repeat) * float64(time.Second) / ppsPerCPU)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
	}
	// The live frame is one byte longer than the largest segment, so every
	// segment resizes it with bpf_xdp_adjust_tail. The kernel refreshes the
	// xdp_frame length after a run only when the program changed data_end;
	// a full-size segment on an unresized frame would otherwise go out with
	// whatever length the previous user of the recycled page left (on veth,
	// the peer's XDP program shrinking it in place into an ACK), i.e. a
	// header-only frame claiming mss bytes of payload.
	// The SYN (headers + options) must not hit that length either.
	liveFrame := append([]byte(nil), template...)
	if synLen := int(t.hdrLen) + tcpSynOptLen; synLen > len(liveFrame) {
		liveFrame = append(liveFrame, make([]byte, synLen-len(liveFrame))...)
	}
	if x.mixed != nil && len(liveFrame) < 2048 {
		liveFrame = append(liveFrame, make([]byte, 2048-len(liveFrame))...)
	}
	liveFrame = append(liveFrame, 0)
	runOpts := &ebpf.RunOptions{
		Data:      liveFrame,
		Repeat:    repeat,
		Flags:     unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context:   coreelf.XdpMd{DataEnd: uint32(len(liveFrame)), IngressIfindex: uint32(x.Device.Index)},
		BatchSize: x.cfg.BatchSize,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	statsDone := make(chan struct{})
	go func() { defer close(statsDone); x.showTCPStats(ctx) }()

	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for k, cpu := range x.cpus {
		txProg := x.bpfobjs.XdpTxTcp
		if x.mixed != nil {
			txProg = x.bpfobjs.XdpTxMixed
		}
		p, err := txProg.Clone()
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(slot, cpu int, p *ebpf.Program) {
			defer wg.Done()
			defer p.Close()
			if err := x.tcpWorker(ctx, cpu, p, runOpts, interval); err != nil {
				x.Logger.Error("tcp worker failed", zap.Int("cpu", cpu), zap.Int("slot", slot), zap.Error(err))
				once.Do(func() { firstErr = err; cancel() })
			}
		}(k, cpu, p)
	}
	x.Logger.Info("TCP stream started", zap.Int("workers", len(x.cpus)), zap.Uint32("repeat", repeat), zap.Duration("interval", interval))

	// Completion: all flows DONE/FAILED/SKIPPED, --duration elapsed (then
	// drain), or a signal (drain; a second one aborts).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	flows := uint64(x.cfg.TCPFlows)
	allClosed := func() bool {
		s, err := x.readTCPStats(recs)
		return err == nil && s.Done+s.Failed+s.Skipped >= flows
	}
	var durationCh <-chan time.Time
	if x.cfg.Duration > 0 {
		durationCh = time.After(x.cfg.Duration)
	}
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()

	draining := false
	var drainDeadline <-chan time.Time
	// After the last flow closes, keep the RX program attached for a while so
	// that a retransmitted FIN from the peer is still answered instead of
	// hitting the kernel (which would reply with RST and leave the peer in
	// LAST-ACK).
	var lingerCh <-chan time.Time
	linger := 2 * x.cfg.TCPRTO
	// Covers the longest retry sequence after drain starts (FIN backoff, or
	// the FIN_WAIT_2 ACK probes), plus slack.
	drainTimeout := tcpBackoffSpan*x.cfg.TCPRTO + time.Second
	if x.mixed != nil {
		drainTimeout += mixedDrainSchedulingGrace(flows, uint64(len(x.cpus)), uint64(repeat), interval)
	}
	// Abort: reset every open flow with RST (so the peer does not keep the
	// connection into the next run), give the workers a moment to send them.
	aborting := false
	var abortDeadline <-chan time.Time
	startAbort := func(reason string) {
		if aborting {
			return
		}
		aborting = true
		x.Logger.Warn("aborting: resetting open flows", zap.String("reason", reason))
		if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 1; c.Abort = 1 }); err != nil {
			x.Logger.Warn("failed to set abort flag", zap.Error(err))
		}
		// One RST per TX iteration: with --pps a worker runs `repeat`
		// iterations every `interval`, and in the worst case one worker
		// owns every flow, so it needs ceil(flows/repeat) runs. One more
		// run covers an abort that lands right after a run, and the whole
		// is doubled for slack.
		grace := tcpAbortGrace
		if interval > 0 {
			runs := (flows + uint64(repeat) - 1) / uint64(repeat)
			if need := 2 * time.Duration(runs+1) * interval; need > grace {
				grace = need
			}
		}
		abortDeadline = time.After(grace)
	}
	startDrain := func(reason string) {
		if draining {
			return
		}
		draining = true
		x.Logger.Info("draining: closing all flows", zap.String("reason", reason))
		if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 1 }); err != nil {
			x.Logger.Warn("failed to set drain flag", zap.Error(err))
		}
		drainDeadline = time.After(drainTimeout)
	}
	workersDone := make(chan struct{})
	go func() { wg.Wait(); close(workersDone) }()

loop:
	for {
		select {
		case <-poll.C:
			if lingerCh == nil && allClosed() {
				if x.mixed != nil {
					startDrain("all flows closed")
				}
				lingerCh = time.After(linger)
			}
		case <-lingerCh:
			break loop
		case <-durationCh:
			durationCh = nil
			startDrain("duration elapsed")
		case <-sig:
			if aborting {
				x.Logger.Warn("third signal: exiting immediately")
				break loop
			}
			if draining {
				startAbort("second signal")
				continue
			}
			startDrain("signal")
		case <-drainDeadline:
			drainDeadline = nil
			startAbort("drain timeout: some flows did not close cleanly")
		case <-abortDeadline:
			break loop
		case <-workersDone:
			break loop
		case <-ctx.Done():
			break loop
		}
	}
	cancel()
	wg.Wait()
	<-statsDone // no periodic line after (or interleaved with) the final one
	// Detach RX before the final read: it keeps answering (e.g. a
	// retransmitted FIN) and would bump the counters while they are read.
	if err := lrx.Close(); err != nil {
		x.Logger.Warn("failed to detach TCP RX program", zap.Error(err))
	}

	s, statsErr := x.showTCPFinalStats(recs)
	if x.mixed != nil {
		if err := x.showMixedStats(); err != nil && statsErr == nil {
			statsErr = err
		}
	}
	// The report is written even when flows failed: that is when the
	// per-flow view matters most.
	if err := x.writeTCPFlowReport(); err != nil {
		x.Logger.Error("tcp flow report failed", zap.Error(err))
		if statsErr == nil {
			statsErr = err
		}
	}
	if firstErr != nil {
		return fmt.Errorf("worker failed: %w", firstErr)
	}
	if statsErr != nil {
		return statsErr
	}
	// A run whose flows did not complete is a failed measurement: report it
	// in the exit status, not only in the log (e.g. every SYN refused).
	if s.Failed > 0 {
		return fmt.Errorf("%d of %d flows failed (aborted %d, retransmit give-ups %d, FIN_WAIT_2 timeouts %d)",
			s.Failed, x.cfg.TCPFlows, s.Aborted, s.RtxGiveups, s.FinWait2Timeouts)
	}
	return nil
}

func (x *Xdperf) showTCPFinalStats(recs []coreelf.BpfTcpStats) (coreelf.BpfTcpStats, error) {
	s, err := x.readTCPStats(recs)
	if err != nil {
		return s, fmt.Errorf("failed to read tcp stats: %w", err)
	}
	x.Logger.Info("tcp final statistics",
		zap.Int("flows", x.cfg.TCPFlows),
		zap.Uint64("syn_sent", s.SynSent),
		zap.Uint64("established", s.Established),
		zap.Uint64("done", s.Done),
		zap.Uint64("failed", s.Failed),
		zap.Uint64("rst_rcvd", s.RstRcvd),
		zap.Uint64("data_segments", s.DataSegs),
		zap.Uint64("data_bytes_sent", s.DataBytes),
		zap.Uint64("bytes_acked", s.BytesAcked),
		zap.Uint64("retransmits", s.RtxSegs),
		zap.Uint64("retransmits_timeout", s.RtxTimeouts),
		zap.Uint64("retransmits_dupack", s.RtxDupack),
		zap.Uint64("acks_rcvd", s.AcksRcvd),
		zap.Uint64("acks_sent", s.AcksSent),
		zap.Uint64("window_stalls", s.WindowStalls),
		zap.Uint64("idle_iterations", s.IdleIters),
		zap.Uint64("unexpected", s.Unexpected),
		zap.Uint64("build_errors", s.BuildErrors),
		zap.Uint64("failed_established", s.FailedEst),
		zap.Uint64("skipped", s.Skipped),
		zap.Uint64("aborted", s.Aborted),
		zap.Uint64("rst_sent", s.RstSent),
		zap.Uint64("retransmit_giveups", s.RtxGiveups),
		zap.Uint64("fin_wait2_timeouts", s.FinWait2Timeouts),
		zap.Uint64("ack_probes", s.AckProbes),
		zap.Uint64("window_probes", s.WindowProbes),
		zap.Uint64("challenge_acks", s.ChallengeAcks),
	)
	return s, nil
}
