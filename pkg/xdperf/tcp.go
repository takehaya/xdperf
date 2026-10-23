package xdperf

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
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
// xdp_tx_mixed (driven by bpf_prog_run live frames) and xdp_rx_mixed (attached to
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

// resolveTCPTarget parses the destination, picks the source address and resolves the
// next-hop MAC through the kernel's routing table and neighbor cache.
func (x *Xdperf) resolveTCPTarget(destination string, mss int) (*tcpTarget, error) {
	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP destination %q: %w", destination, err)
	}
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid TCP destination host %q", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid TCP destination port %q", portStr)
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
	t.srcIP = route.Src
	if t.srcIP == nil {
		return nil, fmt.Errorf("could not determine a source address for %s", dstIP)
	}
	if t.ipVersion == 4 {
		if t.srcIP.To4() == nil {
			return nil, fmt.Errorf("source IP %s is not IPv4 but TCP destination is", t.srcIP)
		}
		t.srcIP = t.srcIP.To4()
	} else if t.srcIP.To4() != nil {
		return nil, fmt.Errorf("source IP %s is not IPv6 but TCP destination is", t.srcIP)
	}

	egress, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("route egress link %d: %w", route.LinkIndex, err)
	}
	egressName := egress.Attrs().Name
	if route.LinkIndex != x.Device.Index {
		vlan, ok := egress.(*netlink.Vlan)
		if !ok || vlan.ParentIndex != x.Device.Index {
			return nil, fmt.Errorf("TCP variant route via %s does not use device %s or its VLAN child", egressName, x.Device.Name)
		}
		if vlan.VlanProtocol != netlink.VLAN_PROTOCOL_8021Q {
			return nil, fmt.Errorf("TCP variant route via %s requires an 802.1Q VLAN child; use base_packet for other VLAN protocols", egressName)
		}
		t.vlanID = uint16(vlan.VlanId)
	}
	macStr := plugin.ResolveNeighborMAC(nextHop.String(), egressName)
	if macStr == "" {
		return nil, fmt.Errorf("could not resolve the MAC address of next hop %s via %s", nextHop, egressName)
	}
	t.dstMAC, err = net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("neighbor cache returned an invalid MAC %q: %w", macStr, err)
	}

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

	if err := x.templateMSS(t, mss, 0); err != nil {
		return nil, err
	}
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
		FlowCount:      uint32(x.mixed.connections),
		WindowSegs:     uint32(x.mixed.groups[0].window),
		Mss:            t.mss,
		PortBase:       uint16(x.mixed.portBase),
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
		RtoNs:          uint64(x.mixed.groups[0].rto),
	}
	if x.mixed.repeat {
		cfg.SlotCount = uint32(x.mixed.flows)
	}
	cfg.IpIdShared = x.mixed.groups[0].ipIDShared
	copy(cfg.HdrTmpl[:], template[:min(int(t.l4Off), len(cfg.HdrTmpl))])
	zero := uint32(0)
	if err := x.bpfobjs.TcpCfgMap.Put(&zero, &cfg); err != nil {
		return fmt.Errorf("tcp_cfg_map: %w", err)
	}

	if err := x.initTCPTemplates(t, template, cfg); err != nil {
		return err
	}
	flows := x.mixed.connections
	keys := make([]uint32, flows)
	vals := make([]coreelf.BpfTcpFlow, flows)
	for i := 0; i < flows; i++ {
		keys[i] = uint32(i)
		vals[i] = coreelf.BpfTcpFlow{
			State:       tcpFlowClosed,
			SrcPort:     uint16(x.mixed.portBase + i),
			Iss:         rand.Uint32(),
			BytesTarget: x.tcpVariantBytes[i%x.mixed.flows],
		}
	}
	for j, g := range x.mixed.groups {
		var id uint16
		if len(g.variant.Base.Data) != 0 {
			target, err := parseTCPVariant(g.variant)
			if err != nil {
				return err
			}
			if target.ipVersion == 4 {
				id = binary.BigEndian.Uint16(g.variant.Base.Data[int(target.l3Off)+4:])
			}
		}
		for i := g.first; i < g.first+g.count; i++ {
			for k := int(i); k < flows; k += x.mixed.flows {
				vals[k].TemplateId = g.templateID(i, j)
				vals[k].IpId = id
			}
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

	if x.mixed.repeat {
		for i := 0; i < x.mixed.flows; i++ {
			current := uint32(i)
			if i >= flows {
				current = math.MaxUint32
			}
			if err := x.bpfobjs.TcpSlotMap.Put(uint32(i), current); err != nil {
				return err
			}
			if i >= flows {
				owner := uint32(i % len(x.cpus))
				var closed uint32
				if err := x.bpfobjs.MixedClosedMap.Lookup(owner, &closed); err != nil {
					return err
				}
				if err := x.bpfobjs.MixedClosedMap.Put(owner, closed+1); err != nil {
					return err
				}
			}
		}
	}
	flows = x.mixed.flows
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
// kernel's ephemeral port range: xdp_rx_mixed would then also capture replies
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
	first, last := x.mixed.portBase, x.mixed.portBase+x.mixed.connections-1
	if first <= hi && last >= lo {
		x.Logger.Warn("TCP source ports overlap the kernel's ephemeral port range; host connections to the same destination may be captured by xdp_rx_mixed. Change tcp_port_base or reserve the ports with net.ipv4.ip_local_reserved_ports",
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
	if err := x.bpfobjs.TcpCfgMap.Put(&zero, &cfg); err != nil {
		return err
	}
	for _, id := range x.mixed.templateIDs() {
		var v coreelf.BpfTcpTemplate
		if err := x.bpfobjs.TcpTemplateMap.Lookup(id, &v); err != nil {
			return err
		}
		fn(&v.Cfg)
		if err := x.bpfobjs.TcpTemplateMap.Put(id, v); err != nil {
			return err
		}
	}
	return nil
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

func (x *Xdperf) tcpPortsExhausted() (bool, error) {
	if !x.mixed.untilDuration {
		return false, nil
	}
	// The last connection of every slot must have started before all ports
	// are consumed; a closed last connection then needs an unavailable refill.
	exhausted := false
	for i := max(0, x.mixed.connections-x.mixed.flows); i < x.mixed.connections; i++ {
		var f coreelf.BpfTcpFlow
		if err := x.bpfobjs.TcpFlowMap.Lookup(uint32(i), &f); err != nil {
			return false, fmt.Errorf("tcp_flow_map[%d]: %w", i, err)
		}
		if f.Started == 0 {
			return false, nil
		}
		exhausted = exhausted || f.State == tcpFlowDone || f.State == tcpFlowFailed
	}
	return exhausted, nil
}

func (x *Xdperf) showTCPStats(ctx context.Context, started time.Time) {
	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prev coreelf.BpfTcpStats
	previous := started
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
			now := time.Now()
			seconds := now.Sub(previous).Seconds()
			gbps := float64(safeDelta(cur.BytesAcked, prev.BytesAcked)*8) / 1e9 / seconds
			p.Printf("tcp: est %d done %d fail %d | CPS start %.1f est %.1f done %.1f | %.3f Gbps acked, %d segs/s, %d acks/s, rtx %d/s, stalls %d/s\n",
				tcpActiveFlows(cur), cur.Done, cur.Failed,
				float64(safeDelta(cur.Started, prev.Started))/seconds, float64(safeDelta(cur.Established, prev.Established))/seconds, float64(safeDelta(cur.Done, prev.Done))/seconds, gbps,
				safeDelta(cur.DataSegs, prev.DataSegs), safeDelta(cur.AcksRcvd, prev.AcksRcvd),
				safeDelta(cur.RtxSegs, prev.RtxSegs), safeDelta(cur.WindowStalls, prev.WindowStalls))
			prev, previous = cur, now
		}
	}
}

// tcpWorker drives xdp_tx_mixed on one CPU until ctx is cancelled.
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

// runTCP drives TCP flow variants through the mixed engine.
func (x *Xdperf) runTCP(ctx context.Context) error {
	var t *tcpTarget
	var template []byte
	var err error
	if len(x.mixed.groups[0].variant.Base.Data) != 0 {
		t, err = parseTCPVariant(x.mixed.groups[0].variant)
		if err == nil {
			err = x.templateMSS(t, x.mixed.groups[0].mss, 0)
		}
		template = append([]byte(nil), x.mixed.groups[0].variant.Base.Data...)
	} else {
		t, err = x.resolveTCPTarget(x.mixed.destination, x.mixed.groups[0].mss)
		if err == nil {
			template, err = buildTCPTemplate(t, uint16(x.mixed.portBase))
		}
	}
	if err != nil {
		return err
	}
	if err := x.initTCPMaps(t, template); err != nil {
		return fmt.Errorf("failed to init TCP maps: %w", err)
	}

	for _, id := range x.mixed.templateIDs() {
		var v coreelf.BpfTcpTemplate
		if err := x.bpfobjs.TcpTemplateMap.Lookup(id, &v); err != nil {
			return err
		}
		n := int(v.Cfg.HdrLen) + max(int(v.DataLen)+int(v.Cfg.Mss), int(v.SynLen))
		if v.Timestamps != 0 {
			n += 12
		}
		if n > len(template) {
			template = append(template, make([]byte, n-len(template))...)
		}
	}
	window, rto := x.mixed.groups[0].window, x.mixed.groups[0].rto
	x.Logger.Info("TCP stream target resolved",
		zap.Uint8("ip_version", t.ipVersion),
		zap.String("src", t.srcIP.String()),
		zap.String("dst", net.JoinHostPort(t.dstIP.String(), fmt.Sprint(t.dstPort))),
		zap.String("src_mac", t.srcMAC.String()),
		zap.String("dst_mac", t.dstMAC.String()),
		zap.Uint16("vlan_id", t.vlanID),
		zap.Uint16("mss", t.mss),
		zap.Int("frame_len", len(template)),
		zap.Int("flows", x.mixed.flows),
		zap.Int("port_base", x.mixed.portBase),
		zap.Int("window_segs", window),
		zap.Duration("rto", rto),
	)

	if err := x.initMixedMaps(); err != nil {
		return err
	}
	x.warnEphemeralPortOverlap()

	// The RX program must be in place before the first SYN leaves.
	rxProg := x.bpfobjs.XdpRxMixed
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
	if len(liveFrame) < 2048 {
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

	x.beginSummary()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	statsDone := make(chan struct{})
	started := time.Now()
	go func() { defer close(statsDone); x.showTCPStats(ctx, started) }()

	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	for k, cpu := range x.cpus {
		txProg := x.bpfobjs.XdpTxMixed
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

	// Completion: mixed count reached, all flows DONE/FAILED/SKIPPED, --duration elapsed (then
	// drain), or a signal (drain; a second one aborts).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	flows := uint64(x.mixed.flows)
	budgetStates := make([]coreelf.BpfPktState, len(recs))
	packetCounts := make([]coreelf.BpfDatarec, len(recs))
	countReached := false
	allClosed := func() bool {
		s, err := x.readTCPStats(recs)
		if err != nil {
			return false
		}
		if !x.mixed.repeat {
			return s.Done+s.Failed+s.Skipped >= flows
		}
		for owner := range x.cpus {
			var closed uint32
			if err := x.bpfobjs.MixedClosedMap.Lookup(uint32(owner), &closed); err != nil {
				return false
			}
			count := (x.mixed.flows + len(x.cpus) - 1 - owner) / len(x.cpus)
			if closed < uint32(count) {
				return false
			}
		}
		return true
	}
	var durationCh <-chan time.Time
	if x.cfg.Duration > 0 {
		durationCh = time.After(x.cfg.Duration)
	}
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()

	draining := false
	portExhausted := false
	var loadEnded time.Time
	var loadStats coreelf.BpfTcpStats
	stopReason := "worker stopped"
	var drainDeadline <-chan time.Time
	// After the last flow closes, keep the RX program attached for a while so
	// that a retransmitted FIN from the peer is still answered instead of
	// hitting the kernel (which would reply with RST and leave the peer in
	// LAST-ACK).
	var lingerCh <-chan time.Time
	linger := 2 * x.tcpRTO()
	// Covers the longest retry sequence after drain starts (FIN backoff, or
	// the FIN_WAIT_2 ACK probes), plus slack.
	drainTimeout := tcpBackoffSpan*x.tcpRTO() + time.Second
	drainTimeout += mixedDrainSchedulingGrace(flows, uint64(len(x.cpus)), uint64(repeat), interval)
	// Abort: reset every open flow with RST (so the peer does not keep the
	// connection into the next run), give the workers a moment to send them.
	aborting := false
	var abortDeadline <-chan time.Time
	startAbort := func(reason string) {
		if aborting {
			return
		}
		aborting = true
		stopReason = reason
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
		var err error
		portExhausted, err = x.tcpPortsExhausted()
		if err != nil {
			once.Do(func() { firstErr = err })
		}
		if portExhausted {
			reason = "port_exhausted"
		}
		draining = true
		if loadEnded.IsZero() {
			loadEnded = time.Now()
			loadStats, err = x.readTCPStats(recs)
			if err != nil {
				x.Logger.Warn("failed to read load statistics", zap.Error(err))
				once.Do(func() { firstErr = err })
			}
			stopReason = reason
		}
		if countReached {
			lingerCh = nil
		}
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
			if x.cfg.Count > 0 && !x.cfg.Infinite && !draining && !countReached {
				var remaining int64
				if err := x.bpfobjs.MixedBudgetMap.Lookup(uint32(0), &remaining); err != nil {
					once.Do(func() { firstErr = fmt.Errorf("read TX count pool: %w", err) })
					break loop
				}
				if err := x.bpfobjs.PktStateMap.Lookup(uint32(0), &budgetStates); err != nil {
					once.Do(func() { firstErr = fmt.Errorf("read TX budgets: %w", err) })
					break loop
				}
				if x.mixedCountReached(remaining, budgetStates) {
					// Pool and per-CPU reads can catch a reservation in transit.
					if err := x.bpfobjs.TxStatsMap.Lookup(uint32(0), &packetCounts); err != nil {
						once.Do(func() { firstErr = err })
						break loop
					}
					tcpFlows, err := x.readTCPFlows(x.mixed.connections)
					if err != nil {
						once.Do(func() { firstErr = err })
						break loop
					}
					var sent uint64
					for _, f := range tcpFlows {
						sent += f.TxPkts
					}
					for _, p := range packetCounts {
						sent += p.Packets
					}
					if sent < x.cfg.Count {
						continue
					}
					countReached = true
					loadEnded = time.Now()
					loadStats, err = x.readTCPStats(recs)
					if err != nil {
						once.Do(func() { firstErr = err })
						break loop
					}
					stopReason = "count reached"
					x.Logger.Info("count reached", zap.Uint64("count", x.cfg.Count))
					lingerCh = time.After(linger)
					durationCh, drainDeadline, abortDeadline = nil, nil, nil
				}
			}
			if lingerCh == nil && allClosed() {
				startDrain("all flows closed")
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

	s, statsErr := x.showTCPFinalStats(recs, portExhausted)
	ended := time.Now()
	if loadEnded.IsZero() {
		loadEnded, loadStats = ended, s
	}
	x.showTCPConnectionRates(loadStats, loadEnded.Sub(started), ended.Sub(loadEnded), stopReason)
	if err := x.showMixedStats(); err != nil && statsErr == nil {
		statsErr = err
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
	if countReached && s.Done+s.Failed+s.Skipped < flows {
		x.Logger.Warn(fmt.Sprintf("count reached before %d flows completed", flows-s.Done-s.Failed-s.Skipped))
	}
	// A run whose flows did not complete is a failed measurement: report it
	// in the exit status, not only in the log (e.g. every SYN refused).
	if portExhausted {
		return fmt.Errorf("port_exhausted: fresh TCP source ports exhausted")
	}
	if s.Failed > 0 {
		return fmt.Errorf("%d of %d flows failed (aborted %d, retransmit give-ups %d, FIN_WAIT_2 timeouts %d)",
			s.Failed, x.mixed.connections, s.Aborted, s.RtxGiveups, s.FinWait2Timeouts)
	}
	return x.writeSummary()
}

func (x *Xdperf) showTCPConnectionRates(loadStats coreelf.BpfTcpStats, load, drain time.Duration, reason string) {
	seconds := load.Seconds()
	var startedCPS, establishedCPS, doneCPS float64
	if seconds > 0 {
		startedCPS = float64(loadStats.Started) / seconds
		establishedCPS = float64(loadStats.Established) / seconds
		doneCPS = float64(loadStats.Done) / seconds
	}
	if x.summary != nil && x.summary.TCP != nil {
		s := x.summary.TCP
		s.Reason = reason
		s.LoadSeconds = seconds
		s.DrainLingerSeconds = drain.Seconds()
		s.StartedCPS = startedCPS
		s.EstablishedCPS = establishedCPS
		s.DoneCPS = doneCPS
	}
	x.Logger.Info("tcp connection rates", zap.String("reason", reason),
		zap.Float64("load_seconds", seconds), zap.Float64("drain_linger_seconds", drain.Seconds()),
		zap.Float64("started_cps", startedCPS),
		zap.Float64("established_cps", establishedCPS),
		zap.Float64("done_cps", doneCPS))
}

func (x *Xdperf) showTCPFinalStats(recs []coreelf.BpfTcpStats, portExhausted bool) (coreelf.BpfTcpStats, error) {
	s, err := x.readTCPStats(recs)
	if err != nil {
		return s, fmt.Errorf("failed to read tcp stats: %w", err)
	}
	if x.summary != nil {
		x.summary.TCP = &tcpSummary{
			Flows:              x.mixed.flows,
			Started:            s.Started,
			PortExhausted:      portExhausted,
			SynSent:            s.SynSent,
			Established:        s.Established,
			Done:               s.Done,
			Failed:             s.Failed,
			RstRcvd:            s.RstRcvd,
			DataSegments:       s.DataSegs,
			DataBytesSent:      s.DataBytes,
			BytesAcked:         s.BytesAcked,
			Retransmits:        s.RtxSegs,
			RetransmitsTimeout: s.RtxTimeouts,
			RetransmitsDupack:  s.RtxDupack,
			AcksRcvd:           s.AcksRcvd,
			AcksSent:           s.AcksSent,
			WindowStalls:       s.WindowStalls,
			IdleIterations:     s.IdleIters,
			Unexpected:         s.Unexpected,
			BuildErrors:        s.BuildErrors,
			FailedEstablished:  s.FailedEst,
			Skipped:            s.Skipped,
			Aborted:            s.Aborted,
			RstSent:            s.RstSent,
			RetransmitGiveups:  s.RtxGiveups,
			FinWait2Timeouts:   s.FinWait2Timeouts,
			AckProbes:          s.AckProbes,
			WindowProbes:       s.WindowProbes,
			ChallengeAcks:      s.ChallengeAcks,
		}
	}
	x.Logger.Info("tcp final statistics",
		zap.Int("flows", x.mixed.flows),
		zap.Uint64("started", s.Started),
		zap.Bool("port_exhausted", portExhausted),
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
