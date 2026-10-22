package xdperf

import (
	"bytes"
	"math"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func TestMixedBPFDispatch(t *testing.T) {
	cpu := pinMixedTestCPU(t)
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{cfg: mixedConfig(), bpfSpec: spec, cpus: []int{cpu}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants[1].TCPFlow.Flows[0].Bytes = "18446744073709551615"
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	objs := loadMixedTestObjects(t, x.mixed.features)
	x.bpfobjs = objs
	target := &tcpTarget{srcIP: net.ParseIP("192.0.2.1").To4(), dstIP: net.ParseIP("192.0.2.2").To4(), srcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, dstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, ipVersion: 4, mss: 1024, dstPort: 5201, l3Off: 14, l4Off: 34, hdrLen: 54}
	template, err := buildTCPTemplate(target, 40000)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.initTCPMaps(target, template); err != nil {
		t.Fatal(err)
	}
	flows, err := x.readTCPFlows(4)
	if err != nil {
		t.Fatal(err)
	}
	if flows[0].BytesTarget != math.MaxUint64 || flows[3].BytesTarget != 67108864 {
		t.Fatal("map target precision")
	}
	if err := x.initMixedMaps(); err != nil {
		t.Fatal(err)
	}
	budgets := make([]coreelf.BpfPktState, ebpf.MustPossibleCPU())
	readBudget := func() uint64 {
		t.Helper()
		if err := objs.PktStateMap.Lookup(uint32(0), &budgets); err != nil {
			t.Fatal(err)
		}
		return budgets[cpu].Budget
	}
	readBudget()
	budgets[cpu].Budget = 100000
	if err := objs.PktStateMap.Put(uint32(0), budgets); err != nil {
		t.Fatal(err)
	}
	before := readBudget()
	// Mark all flows done to ensure TCP opportunities stall instead of borrowing
	// packet opportunities. Run each test iteration on the configured CPU.
	for i := range flows {
		flows[i].State = tcpFlowDone
		if err := objs.TcpFlowMap.Put(uint32(i), flows[i]); err != nil {
			t.Fatal(err)
		}
	}
	_, err = objs.XdpTxMixed.Run(&ebpf.RunOptions{Data: make([]byte, 2049), Repeat: 20000})
	if err != nil {
		t.Fatal(err)
	}
	states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
	if err := objs.MixedStateMap.Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	s := states[cpu]
	total := s.PacketOpportunities + s.TcpOpportunities
	if total != 20000 || s.Errors != 0 {
		t.Fatalf("dispatch: %+v", s)
	}
	ratio := float64(s.TcpOpportunities) / float64(total)
	if math.Abs(ratio-0.25) > 0.02 {
		t.Fatalf("ratio=%v", ratio)
	}
	packets := make([]coreelf.BpfDatarec, len(states))
	if err := objs.TxStatsMap.Lookup(uint32(0), &packets); err != nil {
		t.Fatal(err)
	}
	if packets[cpu].Packets != s.PacketOpportunities {
		t.Fatalf("packet count=%d opportunities=%d", packets[cpu].Packets, s.PacketOpportunities)
	}
	if got := readBudget(); got != before-packets[cpu].Packets {
		t.Fatalf("packet TX and TCP idle budget: %d, want %d", got, before-packets[cpu].Packets)
	}
	// A recycled UDP frame must not contaminate TCP's all-zero payload.
	selectMixedTestFlow(t, objs, 0)
	f := coreelf.BpfTcpFlow{State: tcpFlowEstablished, SrcPort: 40000, Iss: 100, SndUna: 101, SndNxt: 101, SndMax: 101, RcvNxt: 5001, SndWnd: 1 << 30, Mss: 1024, BytesTarget: 1024}
	if err := objs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	before = readBudget()
	action, frame, err := objs.XdpTxTcpMixed.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil {
		t.Fatal(err)
	}
	if action != 3 || len(frame) != 1078 || !bytes.Equal(frame[54:], make([]byte, 1024)) {
		t.Fatalf("TCP payload contamination: action=%d len=%d", action, len(frame))
	}

	if got := readBudget(); got != before-1 {
		t.Fatalf("TCP TX budget: %d, want %d", got, before-1)
	}
	// A failed build must not consume a frame budget.
	f.SndNxt, f.SndMax = 101, 101
	if err := objs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	before = readBudget()
	var tmpl coreelf.BpfTcpTemplate
	if err := objs.TcpTemplateMap.Lookup(uint32(0), &tmpl); err != nil {
		t.Fatal(err)
	}
	tmpl.Cfg.L4Off = 237
	if err := objs.TcpTemplateMap.Put(uint32(0), tmpl); err != nil {
		t.Fatal(err)
	}
	action, _, err = objs.XdpTxTcpMixed.Test(make([]byte, 2049))
	if err != nil || action != 1 {
		t.Fatalf("failed build: action=%d err=%v", action, err)
	}
	if got := readBudget(); got != before {
		t.Fatalf("failed build consumed budget: %d, want %d", got, before)
	}
	// Exhaustion blocks normal dispatch; drain must still close TCP flows.
	budgets[cpu].Budget = 0
	if err := objs.PktStateMap.Put(uint32(0), budgets); err != nil {
		t.Fatal(err)
	}
	if err := objs.MixedBudgetMap.Put(uint32(0), int64(0)); err != nil {
		t.Fatal(err)
	}
	for _, drain := range []uint8{0, 1} {
		if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = drain }); err != nil {
			t.Fatal(err)
		}
		action, _, err = objs.XdpTxMixed.Test(make([]byte, 2049))
		if err != nil || action != 1 {
			t.Fatalf("exhausted drain=%d: action=%d err=%v", drain, action, err)
		}
		if got := readBudget(); got != 0 {
			t.Fatalf("exhausted budget wrapped: %d", got)
		}
	}

	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 0 }); err != nil {
		t.Fatal(err)
	}
	cfg := coreelf.BpfMixedCfg{TotalWeight: 1, PacketWeight: 1, Workers: 1, CountLimited: 1}
	if err := objs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual BPF borrowing calculation and the nonpositive pool.
	for _, remaining := range []int64{1600, 17, 1, 0, -7} {
		budgets[cpu].Budget = 0
		if err := objs.PktStateMap.Put(uint32(0), budgets); err != nil {
			t.Fatal(err)
		}
		if err := objs.MixedBudgetMap.Put(uint32(0), remaining); err != nil {
			t.Fatal(err)
		}
		action, _, err := objs.XdpTxMixed.Test(make([]byte, 2049))
		if err != nil {
			t.Fatal(err)
		}
		chunk := max(int64(1), remaining/16)
		wantAction, wantLocal, wantPool := uint32(1), uint64(0), remaining
		if remaining > 0 {
			wantAction, wantLocal, wantPool = 3, uint64(chunk-1), remaining-chunk
		}
		var pool int64
		if err := objs.MixedBudgetMap.Lookup(uint32(0), &pool); err != nil {
			t.Fatal(err)
		}
		if got := readBudget(); action != wantAction || got != wantLocal || pool != wantPool {
			t.Fatalf("pool %d: action/local/pool %d/%d/%d, want %d/%d/%d", remaining, action, got, pool, wantAction, wantLocal, wantPool)
		}
	}
	// No-flow workers do not reserve; a fully closed owner returns its local.
	cfg.PacketWeight, cfg.Workers = 0, 2
	if err := objs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
		t.Fatal(err)
	}
	owners := make([]coreelf.BpfTcpCpuState, len(budgets))
	for _, count := range []uint32{0, 1} {
		owners[cpu] = coreelf.BpfTcpCpuState{First: 0, Count: count, Stride: 2}
		if err := objs.TcpCpuStateMap.Put(uint32(0), owners); err != nil {
			t.Fatal(err)
		}
		if err := objs.MixedClosedMap.Put(uint32(0), uint32(1)); err != nil {
			t.Fatal(err)
		}
		budgets[cpu].Budget = uint64(count) * 5
		if err := objs.PktStateMap.Put(uint32(0), budgets); err != nil {
			t.Fatal(err)
		}
		if err := objs.MixedBudgetMap.Put(uint32(0), int64(3)); err != nil {
			t.Fatal(err)
		}
		action, _, err := objs.XdpTxMixed.Test(make([]byte, 2049))
		var pool int64
		if err := objs.MixedBudgetMap.Lookup(uint32(0), &pool); err != nil {
			t.Fatal(err)
		}
		if err != nil || action != 1 || readBudget() != 0 || pool != 3+int64(count)*5 {
			t.Fatalf("owner count %d: action=%d pool=%d err=%v", count, action, pool, err)
		}
	}
	// Drain sends a FIN even when the count pool and local are exhausted.
	tmpl.Cfg.L4Off = 34
	if err := objs.TcpTemplateMap.Put(uint32(0), tmpl); err != nil {
		t.Fatal(err)
	}
	if err := objs.MixedClosedMap.Put(uint32(0), uint32(0)); err != nil {
		t.Fatal(err)
	}
	f.SndNxt, f.SndMax = 101, 101
	if err := objs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 1 }); err != nil {
		t.Fatal(err)
	}
	action, _, err = objs.XdpTxMixed.Test(make([]byte, 2049))
	if err != nil || action != 3 || readBudget() != 0 {
		t.Fatalf("drain: action=%d err=%v", action, err)
	}

	// A TX terminal transition is counted once, even on repeated visits.
	if err := x.updateTCPCfg(func(c *coreelf.BpfTcpCfg) { c.Drain = 0 }); err != nil {
		t.Fatal(err)
	}
	f.State, f.SynRetries, f.LastSendNs = tcpFlowSynSent, 255, 0
	if err := objs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		action, _, err = objs.XdpTxTcpMixed.Test(make([]byte, 2049))
		if err != nil || action != 1 {
			t.Fatalf("terminal transition: action=%d err=%v", action, err)
		}
		var closed uint32
		if err := objs.MixedClosedMap.Lookup(uint32(0), &closed); err != nil {
			t.Fatal(err)
		}
		if closed != 1 {
			t.Fatalf("closed=%d, want 1", closed)
		}
	}

	// Uneven groups must retain the global owner when drain uses legacy cursors.
	if len(states) < 2 {
		return
	}
	r = mixedResponse()
	group := r.VariablePacketTemplate.Variants[1]
	group.TCPFlow.Flows = []guest.TCPFlow{{Bytes: "0"}, {Bytes: "9007199254740993"}, {Bytes: "18446744073709551615"}}
	r.VariablePacketTemplate.Variants[1] = group
	r.VariablePacketTemplate.Variants = append(r.VariablePacketTemplate.Variants, guest.PacketVariant{Kind: "tcp_flow", Weight: 2, TCPFlow: &guest.TCPFlowVariant{Destination: group.TCPFlow.Destination, Flows: []guest.TCPFlow{{Bytes: "65537"}}}})
	x.cfg = mixedConfig()
	x.cfg.Duration = time.Second
	x.cfg.Parallelism = 2
	x.cpus = []int{0, 1}
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if err := x.initTCPMaps(target, template); err != nil {
		t.Fatal(err)
	}
	if err := x.initMixedMaps(); err != nil {
		t.Fatal(err)
	}
	flows, err = x.readTCPFlows(4)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint64{0, 1<<53 + 1, math.MaxUint64, 65537} {
		if flows[i].BytesTarget != want {
			t.Fatalf("flow %d target=%d want=%d", i, flows[i].BytesTarget, want)
		}
	}
	for i := 0; i < 2; i++ {
		groups := make([]coreelf.BpfMixedGroup, len(states))
		if err := objs.MixedGroupMap.Lookup(uint32(i), &groups); err != nil {
			t.Fatal(err)
		}
		for worker, g := range groups {
			for j := uint32(0); j < g.Count; j++ {
				idx := g.First + j*2
				if idx%2 != uint32(worker) || idx >= 4 {
					t.Fatalf("group%d worker%d: %+v", i, worker, g)
				}
			}
		}
		if i == 0 && (groups[0].Count != 2 || groups[1].Count != 1) {
			t.Fatalf("group 0: %+v", groups[:2])
		}
		if i == 1 && (groups[0].Count != 0 || groups[1].Count != 1 || groups[1].First != 3) {
			t.Fatalf("group 1: %+v", groups[:2])
		}
	}

}

func pinMixedTestCPU(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var old unix.CPUSet
	if err := unix.SchedGetaffinity(0, &old); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !old.IsSet(cpu) {
		cpu++
	}
	var pinned unix.CPUSet
	pinned.Set(cpu)
	if err := unix.SchedSetaffinity(0, &pinned); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.SchedSetaffinity(0, &old); err != nil {
			t.Error(err)
		}
	})
	return cpu
}

func TestMixedBPFScan(t *testing.T) {
	v := extensionVariant(false)
	x := setupFlowExtensions(t, v)
	objs := x.bpfobjs
	n := ebpf.MustPossibleCPU()
	for _, tc := range []struct {
		name                            string
		count, cursor, live, ownerCount uint32
		wantAction, wantCursor          uint32
	}{
		{"eighth", 8, 0, 17, 8, 3, 8},
		{"ninth waits", 9, 0, 19, 9, 1, 8},
		{"cursor wraps", 8, 8, 3, 8, 3, 1},
		{"scan crosses end", 8, 7, 15, 8, 3, 7},
		{"idle", 8, 0, 1, 8, 1, 8},
		{"empty group", 0, 0, 1, 8, 1, 0},
		{"empty worker", 8, 0, 3, 0, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpu := pinMixedTestCPU(t)
			// Group 1 owns odd indices from 3; template 0 and flow 1 are separate.
			cfg := coreelf.BpfMixedCfg{TotalWeight: 1, Groups: 2, Workers: 2, CountLimited: 1}
			if err := objs.MixedCfgMap.Put(uint32(0), cfg); err != nil {
				t.Fatal(err)
			}
			groups := make([]coreelf.BpfMixedGroup, n)
			groups[cpu] = coreelf.BpfMixedGroup{Upper: 1, First: 3, Count: tc.count, Cursor: tc.cursor}
			if err := objs.MixedGroupMap.Put(uint32(1), groups); err != nil {
				t.Fatal(err)
			}
			owners := make([]coreelf.BpfTcpCpuState, n)
			owners[cpu] = coreelf.BpfTcpCpuState{First: 1, Stride: 2, Count: tc.ownerCount}
			if err := objs.TcpCpuStateMap.Put(uint32(0), owners); err != nil {
				t.Fatal(err)
			}
			budgets := make([]coreelf.BpfPktState, n)
			budgets[cpu].Budget = 1
			if err := objs.PktStateMap.Put(uint32(0), budgets); err != nil {
				t.Fatal(err)
			}
			if err := objs.MixedBudgetMap.Put(uint32(0), int64(0)); err != nil {
				t.Fatal(err)
			}
			for idx := uint32(0); idx < 21; idx++ {
				f := coreelf.BpfTcpFlow{State: tcpFlowDone}
				if idx == tc.live || idx == 1 {
					f = coreelf.BpfTcpFlow{State: tcpFlowClosed, SrcPort: uint16(40000 + idx), Mss: 1024, BytesTarget: 1024}
				}
				if err := objs.TcpFlowMap.Put(idx, f); err != nil {
					t.Fatal(err)
				}
			}
			action, _, err := objs.XdpTxMixed.Test(make([]byte, 2049))
			if err != nil || action != tc.wantAction {
				t.Fatalf("action=%d want=%d: %v", action, tc.wantAction, err)
			}
			if err := objs.MixedGroupMap.Lookup(uint32(1), &groups); err != nil {
				t.Fatal(err)
			}
			if groups[cpu].Cursor != tc.wantCursor {
				t.Fatalf("cursor=%d want=%d", groups[cpu].Cursor, tc.wantCursor)
			}
			states := make([]coreelf.BpfMixedState, n)
			if err := objs.MixedStateMap.Lookup(uint32(0), &states); err != nil {
				t.Fatal(err)
			}
			if tc.ownerCount != 0 && tc.count != 0 && states[cpu].SelectedGroup != 1 {
				t.Fatalf("selected group=%d", states[cpu].SelectedGroup)
			}
			if err := objs.PktStateMap.Lookup(uint32(0), &budgets); err != nil {
				t.Fatal(err)
			}
			wantBudget := uint64(1)
			if tc.wantAction == 3 {
				wantBudget = 0
			}
			if budgets[cpu].Budget != wantBudget {
				t.Fatalf("budget=%d want=%d", budgets[cpu].Budget, wantBudget)
			}
			var outside coreelf.BpfTcpFlow
			if err := objs.TcpFlowMap.Lookup(uint32(1), &outside); err != nil {
				t.Fatal(err)
			}
			if outside.TxPkts != 0 {
				t.Fatal("sent a flow outside the group")
			}
			if tc.wantAction == 3 {
				// One remaining frame permits exactly one send across iterations.
				action, _, err = objs.XdpTxMixed.Test(make([]byte, 2049))
				if err != nil || action != 1 {
					t.Fatalf("exhausted action=%d: %v", action, err)
				}
				var sent coreelf.BpfTcpFlow
				if err := objs.TcpFlowMap.Lookup(tc.live, &sent); err != nil {
					t.Fatal(err)
				}
				if sent.TxPkts != 1 {
					t.Fatalf("sent %d frames", sent.TxPkts)
				}
			}
		})
	}
}
