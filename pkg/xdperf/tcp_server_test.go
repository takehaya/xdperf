package xdperf

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

// Every uint64 counter must be summed: fill each field with 1 on every CPU
// and expect the CPU count everywhere.
func TestSumPerCPUCoversEveryCounter(t *testing.T) {
	check := func(t *testing.T, recs any, sum any, n int) {
		t.Helper()
		v := reflect.ValueOf(sum)
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Kind() == reflect.Uint64 && f.Uint() != uint64(n) {
				t.Errorf("%s = %d, want %d", v.Type().Field(i).Name, f.Uint(), n)
			}
		}
	}
	fill := func(p any) {
		v := reflect.ValueOf(p).Elem()
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.Kind() == reflect.Uint64 && f.CanSet() {
				f.SetUint(1)
			}
		}
	}
	const n = 3
	cli := make([]coreelf.BpfTcpStats, n)
	srv := make([]coreelf.BpfTcpSrvStats, n)
	for i := 0; i < n; i++ {
		fill(&cli[i])
		fill(&srv[i])
	}
	check(t, cli, sumPerCPU(cli), n)
	check(t, srv, sumPerCPU(srv), n)
}

func TestTcpActiveFlowsNeverUnderflows(t *testing.T) {
	// SYNs that never got an answer: failed but never established.
	s := coreelf.BpfTcpStats{Established: 2, Done: 1, Failed: 10, FailedEst: 1}
	if got := tcpActiveFlows(s); got != 0 {
		t.Fatalf("active = %d, want 0", got)
	}
	s = coreelf.BpfTcpStats{Established: 5, Done: 1, Failed: 10, FailedEst: 1}
	if got := tcpActiveFlows(s); got != 3 {
		t.Fatalf("active = %d, want 3", got)
	}
}

func TestTCPServerSweepAfterDefault(t *testing.T) {
	x := &Xdperf{cfg: Config{TCPRTO: 200 * time.Millisecond}}
	if got := x.tcpServerSweepAfter(); got != 13*time.Second {
		t.Fatalf("default = %v, want 65*rto = 13s", got)
	}
	x.cfg.TCPRTO = time.Millisecond
	if got := x.tcpServerSweepAfter(); got != 2*time.Second {
		t.Fatalf("small rto: %v, want the 2s floor", got)
	}
	x.cfg.TCPSweepAfter = 5 * time.Second
	if got := x.tcpServerSweepAfter(); got != 5*time.Second {
		t.Fatalf("explicit: %v", got)
	}
}

// The sweeper retires only idle LAST_ACK / SYN_RCVD entries, counts each one
// once, and with stale = 0 (shutdown) retires every such entry.
func TestSweepTCPServerFlows(t *testing.T) {
	objs, _, err := coreelf.ReadBaseCollectionWithSizes(map[string]any{"swap_resp": uint32(0)},
		map[string]uint32{"diff_map": 1, "tcp_srv_flow_map": 64})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer objs.Close()
	x := &Xdperf{bpfobjs: objs, Logger: zap.NewNop(), cfg: Config{TCPRTO: 200 * time.Millisecond}}

	now, err := monotonicNow()
	if err != nil {
		t.Fatal(err)
	}
	if now < uint64(2*time.Minute) {
		t.Skip("host booted less than 2 minutes ago: cannot fake an old timestamp")
	}
	old := now - uint64(time.Minute)
	entries := map[uint16]coreelf.BpfTcpSrvFlow{
		1: {State: tcpSrvLastAck, Iss: 1, LastNs: old},     // swept, closed_implicit
		2: {State: tcpSrvLastAck, Iss: 2, LastNs: now},     // fresh: kept
		3: {State: tcpSrvSynRcvd, Iss: 3, LastNs: old},     // swept, syn_timeouts
		4: {State: tcpSrvEstablished, Iss: 4, LastNs: old}, // established: never swept
	}
	for port, v := range entries {
		k := coreelf.BpfTcpSrvKey{Port: port}
		if err := objs.TcpSrvFlowMap.Put(&k, &v); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(port uint16) bool {
		k := coreelf.BpfTcpSrvKey{Port: port}
		var v coreelf.BpfTcpSrvFlow
		err := objs.TcpSrvFlowMap.Lookup(&k, &v)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}

	sw := &tcpServerSweep{}
	if err := x.sweepTCPServerFlows(sw, uint64(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if exists(1) || !exists(2) || exists(3) || !exists(4) {
		t.Fatalf("after sweep: 1=%v 2=%v 3=%v 4=%v", exists(1), exists(2), exists(3), exists(4))
	}
	if sw.closedImplicit.Load() != 1 || sw.synTimeouts.Load() != 1 {
		t.Fatalf("counts: closed_implicit %d syn_timeouts %d", sw.closedImplicit.Load(), sw.synTimeouts.Load())
	}
	// A second sweep finds nothing new (no double counting).
	if err := x.sweepTCPServerFlows(sw, uint64(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if sw.closedImplicit.Load() != 1 {
		t.Fatalf("double counted: %d", sw.closedImplicit.Load())
	}
	// Shutdown sweep: the fresh LAST_ACK goes too, ESTABLISHED stays.
	if err := x.sweepTCPServerFlows(sw, 0); err != nil {
		t.Fatal(err)
	}
	if exists(2) || !exists(4) || sw.closedImplicit.Load() != 2 {
		t.Fatalf("shutdown sweep: 2=%v 4=%v closed_implicit %d", exists(2), exists(4), sw.closedImplicit.Load())
	}
}
