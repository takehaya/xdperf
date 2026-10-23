package xdperf

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func TestTCPCPSValidation(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		cps, delay                uint32
		connections               *uint32
		pps                       uint64
		report, params, wantError bool
	}{
		{name: "default", connections: ptrConnections(0)},
		{name: "minimum", cps: 1000, delay: 1000, connections: ptrConnections(0)},
		{name: "short quarantine", delay: 999, connections: ptrConnections(0), wantError: true},
		{name: "missing connections", cps: 1, wantError: true},
		{name: "unrequested quarantine", delay: 1000, wantError: true},
		{name: "nanosecond limit", cps: 1000000001, connections: ptrConnections(0), wantError: true},
		{name: "pps", cps: 1, connections: ptrConnections(0), pps: 1, wantError: true},
		{name: "reused CSV", connections: ptrConnections(0), report: true, wantError: true},
		{name: "finite CSV", connections: ptrConnections(5), report: true},
		{name: "finite reused CSV", connections: ptrConnections(60000), report: true, wantError: true},
		{name: "reused variable IP", connections: ptrConnections(0), params: true, wantError: true},
		{name: "cps variable IP", cps: 1, connections: ptrConnections(5), params: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mixedResponse()
			r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[1:]
			v := &r.VariablePacketTemplate.Variants[0]
			v.TCPFlow.Connections, v.TCPFlow.CPS, v.TCPFlow.PortReuseDelayMillis = tc.connections, tc.cps, tc.delay
			if tc.params {
				v.Params = []guest.VariableParams{{ByteStart: 29, ByteSize: 1, ByteRange: guest.TemplateRange{Start: 10, End: 13}, PatternType: guest.ValuePatternTypeSequential}}
			}
			cfg := mixedConfig()
			cfg.Count = 0
			cfg.Duration = time.Second
			cfg.PPS = tc.pps
			if tc.report {
				cfg.TCPFlowReport = "flows.csv"
			}
			x := &Xdperf{cfg: cfg, Logger: zap.NewNop()}
			err := x.prepareMixed(r)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if err == nil && x.mixed.portReuseDelay < time.Second {
				t.Fatal("missing default quarantine")
			}
		})
	}
}

func TestTCPPortReuseBPF(t *testing.T) {
	// Five ports shared by two slots exercises P%N != 0 and both wrap points.
	r := mixedResponse()
	r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[1:]
	r.VariablePacketTemplate.TCPPortBase = 65531
	v := &r.VariablePacketTemplate.Variants[0]
	v.Base = tcpTestBase(false, 0)
	v.TCPFlow.Flows = v.TCPFlow.Flows[:2]
	v.TCPFlow.Connections = ptrConnections(12)
	v.TCPFlow.PortReuseDelayMillis = 1000
	cfg := mixedConfig()
	cfg.Count = 0
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{bpfSpec: spec, cfg: cfg, Device: &net.Interface{MTU: 1500}, cpus: []int{0}, Logger: zap.NewNop()}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	x.bpfobjs = loadMixedTestObjects(t, x.mixed.features)
	target, _ := parseTCPBase(v.Base)
	target.mss = 1024
	if err := x.initTCPMaps(target, v.Base.Data); err != nil {
		t.Fatal(err)
	}
	if err := x.initMixedMaps(); err != nil {
		t.Fatal(err)
	}
	tx := func() uint32 {
		t.Helper()
		a, _, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	for slot := uint32(0); slot < 2; slot++ {
		selectMixedTestFlow(t, x.bpfobjs, slot)
		for id := uint64(slot); id < 12; id += 2 {
			if a := tx(); a != 3 {
				t.Fatalf("slot %d attempt %d: action %d", slot, id, a)
			}
			var idx uint32
			if err := x.bpfobjs.TcpSlotMap.Lookup(slot, &idx); err != nil {
				t.Fatal(err)
			}
			q := (5-1-slot)/2 + 1
			want := slot + uint32((id-uint64(slot))/2%uint64(q))*2
			f := lookupExtensionFlow(t, x, idx)
			if idx != want || f.ConnectionId != id || f.SrcPort != 65531+uint16(idx) || f.State != tcpFlowSynSent {
				t.Fatalf("index %d want %d: %+v", idx, want, f)
			}
			// DONE and FAILED both quarantine, then become reusable with a new ISN.
			f.State = tcpFlowDone
			if id%4 == 0 {
				f.State = tcpFlowFailed
			}
			f.ClosedNs = 1
			if err := x.bpfobjs.TcpFlowMap.Put(idx, f); err != nil {
				t.Fatal(err)
			}
		}
		tx()
		var idx uint32
		if err := x.bpfobjs.TcpSlotMap.Lookup(slot, &idx); err != nil || idx != ^uint32(0) {
			t.Fatalf("finite limit slot=%d idx=%d %v", slot, idx, err)
		}
	}
	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	stats, err := x.readTCPStats(recs)
	if err != nil || stats.Started != 12 || stats.PortReuses != 7 || stats.TxPkts != 12 {
		t.Fatalf("cumulative stats %+v %v", stats, err)
	}
	// A recent terminal port blocks reuse without consuming the attempt ID.
	if err := x.bpfobjs.TcpSlotMap.Put(uint32(0), uint32(4)); err != nil {
		t.Fatal(err)
	}
	f := lookupExtensionFlow(t, x, 4)
	f.ConnectionId = 4
	if err := x.bpfobjs.TcpFlowMap.Put(uint32(4), f); err != nil {
		t.Fatal(err)
	}
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		t.Fatal(err)
	}
	f = lookupExtensionFlow(t, x, 0)
	f.State = tcpFlowDone
	f.ClosedNs = uint64(clock.Nano())
	if err := x.bpfobjs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	selectMixedTestFlow(t, x.bpfobjs, 0)
	if tx() != 1 || lookupExtensionFlow(t, x, 0).ConnectionId != f.ConnectionId {
		t.Fatal("quarantine was bypassed")
	}

	f.SndMax = 100
	f.RcvNxt = 501
	if err := x.bpfobjs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	rx := func(seq, ack uint32, flags byte) uint32 {
		t.Helper()
		a, _, err := x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(*v, 65531, seq, ack, flags, nil))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if rx(499, 100, 0x11) != 1 || lookupExtensionFlow(t, x, 0).ClosedNs != f.ClosedNs {
		t.Fatal("invalid FIN extended quarantine")
	}
	if rx(500, 99, 0x11) != 1 || lookupExtensionFlow(t, x, 0).ClosedNs != f.ClosedNs {
		t.Fatal("invalid FIN ACK extended quarantine")
	}
	if rx(500, 100, 0x11) != 3 || lookupExtensionFlow(t, x, 0).ClosedNs <= f.ClosedNs {
		t.Fatal("valid FIN did not extend quarantine")
	}
	old := lookupExtensionFlow(t, x, 0)
	rx(500, 100, 0x14)
	if lookupExtensionFlow(t, x, 0).State != tcpFlowDone || lookupExtensionFlow(t, x, 0).ClosedNs != old.ClosedNs {
		t.Fatal("stale RST changed terminal state")
	}
	// Stop boundaries also prevent slot refill before Go sets drain.
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.EndNs = 1 }); err != nil {
		t.Fatal(err)
	}
	tx()
	var idx uint32
	if err := x.bpfobjs.TcpSlotMap.Lookup(uint32(0), &idx); err != nil || idx != ^uint32(0) {
		t.Fatal("end time did not retire slot", idx, err)
	}
	// Low CPS keeps fractional worker shares; uneven finite slot ownership stays exact.
	if ebpf.MustPossibleCPU() >= 2 {
		x.cpus = []int{0, 1}
		x.mixed.flows = 3
		x.mixed.attempts = 11
		x.mixed.cps = 1
		x.cfg.Duration = 2 * time.Second
		if _, err := x.initTCPStartClock(); err != nil {
			t.Fatal(err)
		}
		states := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
		if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &states); err != nil {
			t.Fatal(err)
		}
		if states[0].StartLimit != 7 || states[1].StartLimit != 4 {
			t.Fatalf("worker shares %+v %+v", states[0], states[1])
		}
		x.cpus = []int{0, 1}
		x.mixed.flows = 1
		if _, err := x.initTCPStartClock(); err != nil {
			t.Fatal(err)
		}
		if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &states); err != nil {
			t.Fatal(err)
		}
		if states[1].StartLimit != 0 {
			t.Fatal("idle worker received rate share")
		}
	}

	// Closed-loop PPS gets an immediately eligible first run, even below one second.
	x.mixed.cps = 0
	began, err := x.initTCPStartClock()
	if err != nil {
		t.Fatal(err)
	}
	if began.After(time.Now()) {
		t.Fatal("closed-loop start was delayed")
	}
	var cfgClock coreelf.BpfTcpCfg
	if err := x.bpfobjs.TcpCfgMap.Lookup(uint32(0), &cfgClock); err != nil {
		t.Fatal(err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		t.Fatal(err)
	}
	if cfgClock.StartNs > uint64(clock.Nano()) {
		t.Fatal("first PPS opportunity would be gated")
	}

}

func TestTCPCPSGateBPF(t *testing.T) {
	pinMixedTestCPU(t)
	v := extensionVariant(false)
	x := setupFlowExtensions(t, v)
	selectMixedTestFlow(t, x.bpfobjs, 0)
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.TargetCps = 10; c.SlotCount = 1 }); err != nil {
		t.Fatal(err)
	}
	tx := func() uint32 {
		t.Helper()
		a, _, err := x.bpfobjs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	setGate := func(next uint64) {
		t.Helper()
		if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.StartNs = next }); err != nil {
			t.Fatal(err)
		}
		states := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
		if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &states); err != nil {
			t.Fatal(err)
		}
		for i := range states {
			states[i].StartSeen = 0
		}
		if err := x.bpfobjs.TcpCpuStateMap.Put(uint32(0), states); err != nil {
			t.Fatal(err)
		}
	}
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		t.Fatal(err)
	}
	now := uint64(clock.Nano())
	setGate(now + uint64(time.Hour))
	if tx() != 1 || lookupExtensionFlow(t, x, 0).State != tcpFlowClosed {
		t.Fatal("SYN before permit")
	}
	setGate(now - uint64(350*time.Millisecond))
	if tx() != 3 {
		t.Fatal("due SYN was not sent")
	}
	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	s, err := x.readTCPStats(recs)
	if err != nil || s.Started != 1 || s.StartPermits != 1 || s.StartDroppedLate < 3 || s.StartOpportunities != s.StartDroppedLate+1 {
		t.Fatalf("late gate %+v %v", s, err)
	}
	// Existing traffic continues while the next opening is far in the future.
	setGate(now + uint64(time.Hour))
	f := lookupExtensionFlow(t, x, 0)
	f.State = tcpFlowEstablished
	f.SndUna = 101
	f.SndNxt = 101
	f.SndMax = 101
	f.SndWnd = 65535
	if err := x.bpfobjs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	if tx() != 3 {
		t.Fatal("CPS throttled data")
	}
	// A due opportunity with the only slot busy is discarded, without a SYN.
	setGate(now)
	tx()
	s, err = x.readTCPStats(recs)
	if err != nil || s.StartDroppedBusy != 1 || s.Started != 1 {
		t.Fatalf("busy gate %+v %v", s, err)
	}
	// Shared start/end clocks apply even before the host switches to drain.
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.EndNs = 1 }); err != nil {
		t.Fatal(err)
	}
	f.State = tcpFlowClosed
	if err := x.bpfobjs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	setGate(now)
	if tx() != 1 {
		t.Fatal("SYN after end time")
	}
	// At high rates, count rational opportunities exactly without ns-period rounding.
	before, err := x.readTCPStats(recs)
	if err != nil {
		t.Fatal(err)
	}
	setGate(now - uint64(time.Second))
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.TargetCps = 600000000; c.EndNs = now - uint64(900*time.Millisecond) }); err != nil {
		t.Fatal(err)
	}
	tx()
	s, err = x.readTCPStats(recs)
	if err != nil || s.StartOpportunities-before.StartOpportunities != 60000000 || s.StartDroppedLate-before.StartDroppedLate != 60000000 {
		t.Fatalf("fractional period %+v before %+v %v", s, before, err)
	}
	// Once this worker has granted its finite quota, no extra busy drops accrue.
	setGate(now - uint64(time.Second))
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.TargetCps = 10; c.EndNs = 0; c.Connections = 1 }); err != nil {
		t.Fatal(err)
	}
	states := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
	if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	for i := range states {
		states[i].StartPermits = 1
		states[i].StartLimit = 1
	}
	if err := x.bpfobjs.TcpCpuStateMap.Put(uint32(0), states); err != nil {
		t.Fatal(err)
	}
	before = s
	tx()
	s, err = x.readTCPStats(recs)
	if err != nil || s.StartOpportunities != before.StartOpportunities {
		t.Fatal("finite worker quota exceeded", s, err)
	}

	// Opportunity ownership follows slot IDs, including uneven and sub-worker CPS.
	for _, tc := range []struct {
		slots, rate uint32
		elapsed     time.Duration
		want        [2]uint64
	}{
		{3, 1000, time.Second, [2]uint64{667, 333}},
		{3, 1, 500 * time.Millisecond, [2]uint64{1, 0}},
		{128, 3000, time.Second, [2]uint64{1500, 1500}},
	} {
		for owner := uint32(0); owner < 2; owner++ {
			if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) {
				c.Connections = 0
				c.TargetCps = tc.rate
				c.SlotCount = tc.slots
				c.StartNs = now - uint64(tc.elapsed)
				c.EndNs = now
			}); err != nil {
				t.Fatal(err)
			}
			for i := range states {
				states[i].StartSeen = 0
				states[i].First = owner
				states[i].Stride = 2
				states[i].Count = (tc.slots + 1 - owner) / 2
			}
			if err := x.bpfobjs.TcpCpuStateMap.Put(uint32(0), states); err != nil {
				t.Fatal(err)
			}
			before, err = x.readTCPStats(recs)
			if err != nil {
				t.Fatal(err)
			}
			tx()
			s, err = x.readTCPStats(recs)
			if err != nil || s.StartOpportunities-before.StartOpportunities != tc.want[owner] {
				t.Fatalf("slots=%d rate=%d owner=%d: got %d want %d %v", tc.slots, tc.rate, owner, s.StartOpportunities-before.StartOpportunities, tc.want[owner], err)
			}
		}
	}

}

func TestTCPCPSFairnessBPF(t *testing.T) {
	for _, tc := range []struct {
		count int
		mixed bool
	}{{3, false}, {9, false}, {2, true}, {11, true}} {
		t.Run(strconv.Itoa(tc.count), func(t *testing.T) {
			count := tc.count
			v := extensionVariant(false)
			v.TCPFlow.Flows = make([]guest.TCPFlow, count)
			for i := range v.TCPFlow.Flows {
				v.TCPFlow.Flows[i].Bytes = "1048576"
			}
			x := setupFlowExtensions(t, v)
			if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.TargetCps = 1000000000; c.SlotCount = uint32(count); c.RtoNs = 1 << 56 }); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				f := lookupExtensionFlow(t, x, uint32(i))
				f.State = tcpFlowEstablished
				f.Iss = 100
				f.SndUna = 101
				f.SndNxt = 101
				f.SndMax = 101
				f.RcvNxt = 5001
				f.SndWnd = 65535
				if tc.mixed && i == 1 {
					f.State = tcpFlowClosed
				}
				if tc.mixed && i > 1 {
					f.State = tcpFlowSynSent
				}
				if err := x.bpfobjs.TcpFlowMap.Put(uint32(i), f); err != nil {
					t.Fatal(err)
				}
				if err := x.bpfobjs.TcpSlotMap.Put(uint32(i), uint32(i)); err != nil {
					t.Fatal(err)
				}
			}
			cpus := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
			mixed := make([]coreelf.BpfMixedState, len(cpus))
			for i := range cpus {
				cpus[i] = coreelf.BpfTcpCpuState{Count: uint32(count), Stride: 1}
				mixed[i].SelectedGroup = ^uint32(0)
			}
			if err := x.bpfobjs.TcpCpuStateMap.Put(uint32(0), cpus); err != nil {
				t.Fatal(err)
			}
			if err := x.bpfobjs.MixedStateMap.Put(uint32(0), mixed); err != nil {
				t.Fatal(err)
			}
			// Pin the thread: XDP test-run does not support BPF_F_TEST_RUN_ON_CPU.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var allowed unix.CPUSet
			if err := unix.SchedGetaffinity(0, &allowed); err != nil {
				t.Fatal(err)
			}
			cpu := 0
			for cpu < len(cpus) && !allowed.IsSet(cpu) {
				cpu++
			}
			if cpu == len(cpus) {
				t.Fatal("no allowed test CPU")
			}
			var pinned unix.CPUSet
			pinned.Set(cpu)
			if err := unix.SchedSetaffinity(0, &pinned); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.SchedSetaffinity(0, &allowed); err != nil {
					t.Error(err)
				}
			}()
			opts := ebpf.RunOptions{Data: bytes.Repeat([]byte{0xa5}, 2049), DataOut: make([]byte, 4096)}
			iterations := 2 * count
			if tc.mixed {
				iterations = 4 * count
			}
			syns, data := 0, 0
			for i := 0; i < iterations; i++ {
				opts.DataOut = opts.DataOut[:cap(opts.DataOut)]
				ret, err := x.bpfobjs.XdpTxTcpMixed.Run(&opts)
				if err != nil {
					t.Fatal(err)
				}
				if tc.mixed && ret == 1 {
					continue
				}
				if ret != 3 {
					t.Fatalf("iteration %d: action %d", i, ret)
				}
				port := binary.BigEndian.Uint16(opts.DataOut[34:36])
				if !tc.mixed {
					if want := uint16(40000 + i%count); port != want {
						t.Fatalf("iteration %d: got port %d want %d", i, port, want)
					}
				} else if opts.DataOut[47] == 2 {
					if port != 40001 {
						t.Fatal("unexpected SYN port", port)
					}
					syns++
					f := lookupExtensionFlow(t, x, 1)
					// Rapid peer refusals continually make another start available.
					if _, _, err := x.bpfobjs.XdpRxTcpMixed.Test(extensionReply(v, port, 0, f.Iss+1, 0x14, nil)); err != nil {
						t.Fatal(err)
					}
					if lookupExtensionFlow(t, x, 1).State != tcpFlowFailed {
						t.Fatal("SYN was not refused")
					}
				} else {
					if port != 40000 || (opts.DataOut[47] != 0x10 && opts.DataOut[47] != 0x18) || len(opts.DataOut) <= 54 {
						t.Fatal("unexpected existing-flow action", port, opts.DataOut[47])
					}
					data++
				}
			}
			stats, err := x.readTCPStats(make([]coreelf.BpfTcpStats, len(cpus)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.mixed {
				if syns < 2 || data < 2 || stats.StartDroppedService == 0 {
					t.Fatalf("existing flow starved: syns=%d data=%d stats=%+v", syns, data, stats)
				}
			} else if stats.StartDroppedBusy+stats.StartDroppedScan != uint64(2*count) {
				t.Fatalf("SYN probing did not run every iteration: %+v", stats)
			}
		})
	}
}
