package xdperf

import (
	"math"
	"net"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

func TestTCPConnectionMaps(t *testing.T) {
	if ebpf.MustPossibleCPU() < 3 {
		t.Skip("three worker owners require at least three possible CPUs")
	}
	for _, connections := range []uint32{7, 2} {
		t.Run(strconv.Itoa(int(connections)), func(t *testing.T) {
			resp := mixedResponse()
			resp.VariablePacketTemplate.Variants = resp.VariablePacketTemplate.Variants[1:]
			v := &resp.VariablePacketTemplate.Variants[0]
			v.Base = tcpTestBase(false, 0)
			v.TCPFlow.Connections = &connections
			for i := range v.TCPFlow.Flows {
				v.TCPFlow.Flows[i].Bytes = strconv.Itoa(101 + 100*i)
			}
			v.Params = []guest.VariableParams{{ByteStart: 29, ByteSize: 1, ByteRange: guest.TemplateRange{Start: 10, End: 13}, PatternType: guest.ValuePatternTypeSequential}}
			cfg := mixedConfig()
			cfg.Count = 0
			spec, err := coreelf.LoadBpf()
			if err != nil {
				t.Fatal(err)
			}
			x := &Xdperf{cfg: cfg, Device: &net.Interface{MTU: 1500}, bpfSpec: spec, cpus: []int{0, 1, 2}, Logger: zap.NewNop()}
			if err := x.prepareMixed(resp); err != nil {
				t.Fatal(err)
			}
			x.bpfobjs = loadMixedTestObjects(t, x.mixed.features)
			target, err := parseTCPBase(v.Base)
			if err != nil {
				t.Fatal(err)
			}
			if err := x.initTCPMaps(target, v.Base.Data); err != nil {
				t.Fatal(err)
			}
			if err := x.initMixedMaps(); err != nil {
				t.Fatal(err)
			}
			for j := uint32(0); j < connections; j++ {
				var f coreelf.BpfTcpFlow
				if err := x.bpfobjs.TcpFlowMap.Lookup(j, &f); err != nil {
					t.Fatal(err)
				}
				if f.SrcPort != 40000+uint16(j) || f.BytesTarget != uint64(101+100*(j%4)) || f.TemplateId != 16+j%4 {
					t.Fatalf("connection %d: %+v", j, f)
				}
				var tmpl coreelf.BpfTcpTemplate
				if err := x.bpfobjs.TcpTemplateMap.Lookup(f.TemplateId, &tmpl); err != nil {
					t.Fatal(err)
				}
				if tmpl.Prefix[29] != 10+byte(j%4) {
					t.Fatalf("connection %d: wrong source IP", j)
				}
			}
			for i := uint32(0); i < 4; i++ {
				var current uint32
				if err := x.bpfobjs.TcpSlotMap.Lookup(i, &current); err != nil {
					t.Fatal(err)
				}
				want := i
				if i >= connections {
					want = math.MaxUint32
				}
				if current != want {
					t.Fatalf("slot %d points at %d, want %d", i, current, want)
				}
			}
			states := make([]coreelf.BpfTcpCpuState, ebpf.MustPossibleCPU())
			if err := x.bpfobjs.TcpCpuStateMap.Lookup(uint32(0), &states); err != nil {
				t.Fatal(err)
			}
			for owner, cpu := range x.cpus {
				wantCount := uint32(1)
				if owner == 0 {
					wantCount = 2
				}
				if s := states[cpu]; s.First != uint32(owner) || s.Stride != 3 || s.Count != wantCount {
					t.Fatalf("owner %d: %+v", owner, s)
				}
				var closed uint32
				if err := x.bpfobjs.MixedClosedMap.Lookup(uint32(owner), &closed); err != nil {
					t.Fatal(err)
				}
				wantClosed := uint32(0)
				if connections == 2 && (owner == 0 || owner == 2) {
					wantClosed = 1
				}
				if closed != wantClosed {
					t.Fatalf("owner %d: closed slots=%d want=%d", owner, closed, wantClosed)
				}
			}
		})
	}
}
