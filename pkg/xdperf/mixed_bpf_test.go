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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
	defer func() {
		if err := unix.SchedSetaffinity(0, &old); err != nil {
			t.Error(err)
		}
	}()
	objs, spec, err := coreelf.ReadCollection(map[string]any{"swap_resp": uint32(0)}, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	x := &Xdperf{cfg: mixedConfig(), bpfobjs: objs, bpfSpec: spec, cpus: []int{cpu}, Logger: zap.NewNop()}
	r := mixedResponse()
	r.VariablePacketTemplate.Variants[1].TCPFlow.Flows[0].Bytes = "18446744073709551615"
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
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
	// A recycled UDP frame must not contaminate TCP's all-zero payload.
	states[cpu].Active, states[cpu].SelectedFlow = 1, 0
	if err := objs.MixedStateMap.Put(uint32(0), states); err != nil {
		t.Fatal(err)
	}
	f := coreelf.BpfTcpFlow{State: tcpFlowEstablished, SrcPort: 40000, Iss: 100, SndUna: 101, SndNxt: 101, SndMax: 101, RcvNxt: 5001, SndWnd: 1 << 30, Mss: 1024, BytesTarget: 1024}
	if err := objs.TcpFlowMap.Put(uint32(0), f); err != nil {
		t.Fatal(err)
	}
	action, frame, err := objs.XdpTxTcp.Test(bytes.Repeat([]byte{0xa5}, 2049))
	if err != nil {
		t.Fatal(err)
	}
	if action != 3 || len(frame) != 1078 || !bytes.Equal(frame[54:], make([]byte, 1024)) {
		t.Fatalf("TCP payload contamination: action=%d len=%d", action, len(frame))
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
