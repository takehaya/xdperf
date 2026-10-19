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

type mixedGroup struct{ weight, first, count uint32 }
type mixedPlan struct {
	packets                   guest.GeneratorProcessResponse
	groups                    []mixedGroup
	packetWeight, totalWeight uint32
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
	if x.cfg.TCPDst != "" || x.cfg.TCPBytes != 0 || x.cfg.TCPFlows > 1 {
		return fmt.Errorf("mixed variants supply TCP destination, flows and bytes")
	}
	plan := &mixedPlan{packets: guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeVariable}}
	plan.packets.VariablePacketTemplate.Pattern = set.Pattern
	var targets []uint64
	var destination string
	var total uint64
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
		if f == nil || len(f.Flows) == 0 || len(v.Base.Data) != 0 || v.Base.Length != 0 || len(v.Params) != 0 || len(v.Checksums) != 0 {
			return fmt.Errorf("TCP variant %d requires flows and cannot contain packet fields", i)
		}
		host, port, err := net.SplitHostPort(f.Destination)
		n, portErr := strconv.Atoi(port)
		if err != nil || net.ParseIP(host) == nil || portErr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("TCP variant %d requires an IP literal and port 1..65535", i)
		}
		canonical := net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(n))
		if destination != "" && destination != canonical {
			return fmt.Errorf("TCP variants require one common destination")
		}
		destination = canonical
		if x.cfg.TCPPortBase < 1 || x.cfg.TCPPortBase > 65535 || len(f.Flows) > 65536-x.cfg.TCPPortBase-len(targets) {
			return fmt.Errorf("TCP flows exceed source port capacity")
		}
		plan.groups = append(plan.groups, mixedGroup{v.Weight, uint32(len(targets)), uint32(len(f.Flows))})
		for _, flow := range f.Flows {
			b, err := decimalUint64(flow.Bytes)
			if err != nil {
				return fmt.Errorf("TCP variant %d bytes: %w", i, err)
			}
			if b == 0 && x.cfg.Duration <= 0 {
				return fmt.Errorf("unlimited TCP flow requires --duration")
			}
			targets = append(targets, b)
		}
	}
	if plan.packetWeight == 0 {
		return fmt.Errorf("mixed variants require at least one packet variant")
	}
	plan.totalWeight = uint32(total)
	cfg := x.cfg
	cfg.TCPDst, cfg.TCPFlows = destination, len(targets)
	// Reuse all TCP engine flag validation without changing packet CLI semantics.
	check := cfg
	check.PluginName, check.Count, check.Receiver = "", 0, false
	check.TCPBytes = 1
	if err := check.validateTCP(); err != nil {
		return err
	}
	x.cfg, x.tcpVariantBytes, x.mixed = cfg, targets, plan
	return nil
}

func (x *Xdperf) initMixedMaps() error {
	if err := x.initPacketGeneration(&x.mixed.packets); err != nil {
		return err
	}
	cfg := coreelf.BpfMixedCfg{TotalWeight: x.mixed.totalWeight, PacketWeight: x.mixed.packetWeight, Groups: uint32(len(x.mixed.groups)), Workers: uint32(len(x.cpus))}
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
	flows, err := x.readTCPFlows(x.cfg.TCPFlows)
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
	x.Logger.Info("mixed final statistics", zap.Uint64("packet_opportunities", po), zap.Uint64("tcp_opportunities", to), zap.Uint64("packet_tx", pn), zap.Uint64("tcp_tx", tn), zap.Uint64("tcp_rx_replies", replies), zap.Float64("tcp_tx_ratio", ratio), zap.Uint64("dispatch_errors", dispatchErrors), zap.Uint64("packet_bytes", packetBytes), zap.Uint64("packet_errors", packetErrors), zap.Uint64("packet_rx", rxPackets), zap.String("packet_rx_scope", "outer_udp"), zap.Uint64("drain_opportunities", drain))
	if packetErrors != 0 {
		return fmt.Errorf("packet generation errors: %d", packetErrors)
	}
	if dispatchErrors != 0 {
		return fmt.Errorf("mixed dispatch errors: %d", dispatchErrors)
	}
	return nil
}
