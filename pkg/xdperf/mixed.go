package xdperf

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

// mixedDrainSchedulingGrace allows every flow to be revisited even when
// completed entries consume most rate-limited iterations. Budget a full sweep
// for the initial action and each FIN/probe retry, for both closing phases.
func mixedDrainSchedulingGrace(flows, workers, repeat uint64, interval time.Duration) time.Duration {
	if interval == 0 {
		return 0
	}
	perWorker := (flows + workers - 1) / workers
	batches := (perWorker + repeat - 1) / repeat
	// One extra batch covers drain starting just after a worker's run.
	sweep := time.Duration(batches+1) * interval
	return 2 * (tcpMaxFinRetries + 2) * sweep
}

// decimalUint64 deliberately rejects signs, exponents and whitespace.
func decimalUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("expected a uint64 decimal string")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("expected a uint64 decimal string, got %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

type mixedGroup struct {
	weight, first, count uint32
	templateFirst        uint32
	variant              guest.PacketVariant
	window, mss          int
	rto                  time.Duration
	ipIDShared           uint8
}
type mixedPlan struct {
	packets                   guest.GeneratorProcessResponse
	groups                    []mixedGroup
	packetWeight, totalWeight uint32
	flows, portBase           int
	connections               int // retained states; flows remains the number of concurrent slots
	repeat, untilDuration     bool
	destination               string
	features                  coreelf.MixedProgramFeatures
}

// prepareMixed validates the entire union before committing host configuration.
func (x *Xdperf) prepareMixed(resp *guest.GeneratorProcessResponse) error {
	if resp.TemplateType != guest.GeneratorTemplateTypeVariable {
		return nil
	}
	set := resp.VariablePacketTemplate
	hasTCP := false
	for _, v := range set.Variants {
		switch v.Kind {
		case "", "packet":
			if v.TCPFlow != nil {
				return fmt.Errorf("packet variant cannot contain tcp_flow")
			}
		case "tcp_flow":
			hasTCP = true
		default:
			return fmt.Errorf("unknown variant kind %q", v.Kind)
		}
	}
	if !hasTCP {
		return nil
	}
	if len(set.Variants) > 16 || set.Pattern != guest.VariantSelectionModeMixed {
		return fmt.Errorf("mixed TCP variants require pattern=mixed and at most 16 variants")
	}
	if x.cfg.Infinite || x.cfg.RxDevice != "" || x.cfg.SwapResp {
		return fmt.Errorf("mixed variants do not support --infinite, --rx-device or --swap-resp")
	}
	plan := &mixedPlan{packets: guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeVariable}}
	plan.packets.VariablePacketTemplate.Pattern = set.Pattern
	var targets []uint64
	var destination string
	var total uint64
	portBase := 10000
	if set.TCPPortBase != 0 {
		portBase = int(set.TCPPortBase)
	}
	nextTemplate := uint32(16)
	for i, v := range set.Variants {
		if v.Weight == 0 {
			return fmt.Errorf("mixed variant %d requires positive weight", i)
		}
		total += uint64(v.Weight)
		if total > math.MaxUint32 {
			return fmt.Errorf("mixed weight sum exceeds uint32")
		}
		if v.Kind != "tcp_flow" {
			plan.packetWeight += v.Weight
			plan.packets.VariablePacketTemplate.Variants = append(plan.packets.VariablePacketTemplate.Variants, v)
			continue
		}
		f := v.TCPFlow
		if f == nil || len(f.Flows) == 0 || len(v.Checksums) != 0 {
			return fmt.Errorf("TCP variant %d requires flows and cannot contain checksums", i)
		}
		if f.Connections != nil {
			if len(set.Variants) != 1 || (x.cfg.Count != 0 && !x.cfg.CountFromDuration) {
				return fmt.Errorf("connections requires a single TCP variant and cannot be used with --count")
			}
			plan.repeat = true
			plan.untilDuration = *f.Connections == 0
			if plan.untilDuration && x.cfg.Duration <= 0 {
				return fmt.Errorf("connections=0 requires --duration")
			}
			capacity := 65536 - portBase
			if uint64(*f.Connections) > uint64(capacity) {
				return fmt.Errorf("connections exceeds source port capacity %d", capacity)
			}
			plan.connections = int(*f.Connections)
			if plan.untilDuration {
				plan.connections = capacity
			}
		}
		if err := validateTCPFlowParams(v); err != nil {
			return fmt.Errorf("TCP variant %d: %w", i, err)
		}
		payload, err := tcpPayload(f.PayloadPattern)
		if err != nil {
			return err
		}
		plan.features.Payload = plan.features.Payload || payload.Period != 0
		plan.features.Timestamps = plan.features.Timestamps || f.Timestamps
		if f.Encapsulation != nil && len(v.Base.Data) == 0 {
			return fmt.Errorf("encapsulation requires base_packet")
		}
		if f.Encapsulation != nil {
			p, err := parseTCPEncapsulation(v.Base, f.Encapsulation)
			if err != nil {
				return fmt.Errorf("TCP variant %d: %w", i, err)
			}
			plan.features.Lengths = max(plan.features.Lengths, uint32(len(p.lengths)))
			plan.features.OuterIPs = max(plan.features.OuterIPs, uint32(len(p.ips)))
			plan.features.UDPs = max(plan.features.UDPs, uint32(len(p.udps)))
			for j := range p.udps {
				if f.Encapsulation.UDPChecksums[j].Mode == "lco" {
					plan.features.LCO = true
				}
			}
		}
		dest := f.Destination
		if len(v.Base.Data) != 0 || v.Base.Length != 0 {
			t, err := parseTCPVariant(v)
			if err != nil {
				return fmt.Errorf("TCP variant %d: %w", i, err)
			}
			inferred := net.JoinHostPort(t.dstIP.String(), strconv.Itoa(int(t.dstPort)))
			if dest == "" {
				dest = inferred
			} else {
				h, p, e := net.SplitHostPort(dest)
				n, pe := strconv.Atoi(p)
				if e != nil || pe != nil || !net.ParseIP(h).Equal(t.dstIP) || n != int(t.dstPort) {
					return fmt.Errorf("TCP variant %d destination disagrees with base_packet", i)
				}
			}
		}
		if _, err := tcpFlowOptions(f, true); err != nil {
			return err
		}
		if _, err := tcpFlowOptions(f, false); err != nil {
			return err
		}
		host, port, err := net.SplitHostPort(dest)
		n, portErr := strconv.Atoi(port)
		if err != nil || net.ParseIP(host) == nil || portErr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("TCP variant %d requires an IP literal and port 1..65535", i)
		}
		canonical := net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(n))
		if destination == "" {
			destination = canonical
		}
		if portBase < 1 || portBase > 65535 || len(f.Flows) > 65536 || (!plan.repeat && len(f.Flows) > 65536-portBase-len(targets)) {
			return fmt.Errorf("TCP flows exceed source port capacity")
		}
		group := mixedGroup{weight: v.Weight, first: uint32(len(targets)), count: uint32(len(f.Flows)), variant: v,
			window: 32, rto: 200 * time.Millisecond}
		if f.WindowSegs > 65535 {
			return fmt.Errorf("TCP variant %d window_segs must be in 1..65535 (0 = default)", i)
		}
		if f.WindowSegs != 0 {
			group.window = int(f.WindowSegs)
		}
		if f.MSS != 0 && (f.MSS < tcpMinMSS) {
			return fmt.Errorf("TCP variant %d mss must be 0 (default) or %d..65535", i, tcpMinMSS)
		}
		group.mss = int(f.MSS)
		if f.RTOMillis != 0 {
			group.rto = time.Duration(f.RTOMillis) * time.Millisecond
		}
		if f.IPID != "" && f.IPID != "flow" && f.IPID != "shared" {
			return fmt.Errorf("TCP variant %d ip_id must be flow or shared", i)
		}
		if f.IPID == "shared" {
			group.ipIDShared = 1
		}
		if len(v.Params) != 0 {
			group.templateFirst = nextTemplate
			nextTemplate += group.count
			plan.features.TemplateEntries = nextTemplate
		}
		plan.groups = append(plan.groups, group)
		for _, flow := range f.Flows {
			b, err := decimalUint64(flow.Bytes)
			if err != nil {
				return fmt.Errorf("TCP variant %d bytes: %w", i, err)
			}
			if b == 0 && plan.repeat {
				return fmt.Errorf("connections cannot be used with unlimited bytes (0)")
			}
			if b == 0 && x.cfg.Duration <= 0 && x.cfg.Count == 0 {
				return fmt.Errorf("unlimited TCP flow requires --count or --duration")
			}
			targets = append(targets, b)
		}
	}
	plan.totalWeight = uint32(total)
	plan.destination, plan.flows, plan.portBase = destination, len(targets), portBase
	if !plan.repeat {
		plan.connections = plan.flows
	}
	if x.cfg.Count > math.MaxInt64 && !(plan.repeat && x.cfg.CountFromDuration) {
		return fmt.Errorf("mixed --count must be <= %d", int64(math.MaxInt64))
	}
	if plan.repeat && x.cfg.CountFromDuration {
		x.cfg.Count = 0
	}
	x.tcpVariantBytes, x.mixed = targets, plan
	x.warnMixedWorkers()
	return nil
}

func (x *Xdperf) initMixedMaps() error {
	if x.mixed.packetWeight != 0 {
		if err := x.initPacketGeneration(&x.mixed.packets); err != nil {
			return err
		}
	}
	if x.mixed.packetWeight == 0 {
		if err := x.initPktStateMap(make([]uint32, ebpf.MustPossibleCPU())); err != nil {
			return err
		}
	}
	cfg := coreelf.BpfMixedCfg{TotalWeight: x.mixed.totalWeight, PacketWeight: x.mixed.packetWeight, Groups: uint32(len(x.mixed.groups)), Workers: uint32(len(x.cpus))}
	if x.cfg.Count > 0 && !x.cfg.Infinite {
		cfg.CountLimited = 1
		if err := x.bpfobjs.MixedBudgetMap.Put(uint32(0), int64(x.cfg.Count)); err != nil {
			return err
		}
	}
	if x.cfg.Receiver {
		cfg.Receive = 1
	}
	if err := x.bpfobjs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
		return err
	}
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	upper := x.mixed.packetWeight
	for i, g := range x.mixed.groups {
		upper += g.weight
		entries := make([]coreelf.BpfMixedGroup, numCPU)
		for k, cpu := range x.cpus {
			// Match the global flow index modulo worker count used during drain.
			count := uint32(0)
			offset := (uint32(k) + uint32(len(x.cpus)) - g.first%uint32(len(x.cpus))) % uint32(len(x.cpus))
			if offset < g.count {
				count = (g.count-1-offset)/uint32(len(x.cpus)) + 1
			}
			entries[cpu] = coreelf.BpfMixedGroup{Upper: upper, First: g.first + offset, Count: count}
		}
		if err := x.bpfobjs.MixedGroupMap.Put(uint32(i), entries); err != nil {
			return err
		}
	}
	return nil
}

func (x *Xdperf) showMixedStats() error {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	mix := make([]coreelf.BpfMixedState, n)
	packets := make([]coreelf.BpfDatarec, n)
	if err := x.bpfobjs.MixedStateMap.Lookup(uint32(0), &mix); err != nil {
		return err
	}
	if err := x.bpfobjs.TxStatsMap.Lookup(uint32(0), &packets); err != nil {
		return err
	}
	var po, to, pn, tn, replies, dispatchErrors, packetBytes, packetErrors, rxPackets, drain uint64
	for _, s := range mix {
		po += s.PacketOpportunities
		to += s.TcpOpportunities
		drain += s.DrainOpportunities
		dispatchErrors += s.Errors
	}
	for _, s := range packets {
		pn += s.Packets
		packetBytes += s.Bytes
		packetErrors += s.DiffErrors + s.ChecksumErrors
	}
	if err := x.bpfobjs.RxStatsMap.Lookup(uint32(0), &packets); err != nil {
		return err
	}
	for _, s := range packets {
		rxPackets += s.Packets
	}
	flows, err := x.readTCPFlows(x.mixed.connections)
	if err != nil {
		return err
	}
	for _, f := range flows {
		tn += f.TxPkts
		replies += f.RxReplies
	}
	ratio := float64(0)
	if pn+tn > 0 {
		ratio = float64(tn) / float64(pn+tn)
	}
	rx, err := x.readMixedRXStats()
	if err != nil {
		return err
	}
	fields := []zap.Field{}
	for i, reason := range mixedRXReasons {
		fields = append(fields, zap.Uint64("rx_"+reason, rx[i]))
	}
	if rx[2] != 0 {
		x.Logger.Warn("mixed RX packets in flow port range did not match a template; check peer addresses, ports and NAT", zap.Uint64("rx_tuple_mismatch", rx[2]))
	}
	x.Logger.With(fields...).Info("mixed final statistics", zap.Uint64("packet_opportunities", po), zap.Uint64("tcp_opportunities", to), zap.Uint64("packet_tx", pn), zap.Uint64("tcp_tx", tn), zap.Uint64("tcp_rx_replies", replies), zap.Float64("tcp_tx_ratio", ratio), zap.Uint64("dispatch_errors", dispatchErrors), zap.Uint64("packet_bytes", packetBytes), zap.Uint64("packet_errors", packetErrors), zap.Uint64("packet_rx", rxPackets), zap.String("packet_rx_scope", "outer_udp"), zap.Uint64("drain_opportunities", drain))
	if packetErrors != 0 {
		return fmt.Errorf("packet generation errors: %d", packetErrors)
	}
	if dispatchErrors != 0 {
		return fmt.Errorf("mixed dispatch errors: %d", dispatchErrors)
	}
	return nil
}

// Keep the order in sync with enum mixed_rx_reason in xdp_mixed_rx_stats.h.
var mixedRXReasons = [...]string{"parse_failed", "port_outside", "tuple_mismatch", "neighbor", "other", "invalid_tcp"}

type mixedRXTotals [6]uint64

func (x *Xdperf) readMixedRXStats() (mixedRXTotals, error) {
	recs := make([]coreelf.BpfMixedRxStats, ebpf.MustPossibleCPU())
	if err := x.bpfobjs.MixedRxStatsMap.Lookup(uint32(0), &recs); err != nil {
		return mixedRXTotals{}, err
	}
	var totals mixedRXTotals
	for _, rec := range recs {
		for i, value := range rec.Counts {
			totals[i] += value
		}
	}
	return totals, nil
}

// validateRunBounds needs the plugin response to distinguish finite TCP-only runs.
func (c *Config) validateRunBounds(mixed *mixedPlan) error {
	if c.DurationCountError != nil && (mixed == nil || !mixed.repeat) {
		return c.DurationCountError
	}
	if (mixed == nil || mixed.packetWeight != 0) && c.Count == 0 && c.Duration == 0 {
		return fmt.Errorf("either --count or --duration must be specified")
	}
	if (mixed == nil || mixed.packetWeight != 0) && c.Duration > 0 && c.PPS == 0 {
		return fmt.Errorf("--duration requires --pps to be specified with packet variants")
	}
	return nil
}

func (x *Xdperf) mixedCountReached(remaining int64, states []coreelf.BpfPktState) bool {
	if x.mixed == nil || x.cfg.Count == 0 || x.cfg.Infinite || remaining > 0 {
		return false
	}
	for _, cpu := range x.cpus {
		if states[cpu].Budget != 0 {
			return false
		}
	}
	return true
}

func (x *Xdperf) warnMixedWorkers() {
	if x.mixed.packetWeight == 0 && x.mixed.flows < len(x.cpus) {
		x.Logger.Warn("fewer TCP flows than TX workers: workers without flows remain idle",
			zap.Int("flows", x.mixed.flows), zap.Int("workers", len(x.cpus)))
	}
}

// tcpRTO bounds shutdown by the slowest TCP group.
func (x *Xdperf) tcpRTO() time.Duration {
	var rto time.Duration
	for _, g := range x.mixed.groups {
		rto = max(rto, g.rto)
	}
	return rto
}
