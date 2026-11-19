package xdperf

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"go.uber.org/zap"
)

func u32p(v uint32) *uint32 { return &v }

// exchangeResponse is mixedResponse with every TCP flow set to rounds.
func exchangeResponse(mutate func(f *guest.TCPFlowVariant)) *guest.GeneratorProcessResponse {
	r := mixedResponse()
	f := r.VariablePacketTemplate.Variants[1].TCPFlow
	for i := range f.Flows {
		f.Flows[i] = guest.TCPFlow{Bytes: "100", ResponseBytes: "10000", Rounds: u32p(5)}
	}
	if mutate != nil {
		mutate(f)
	}
	return r
}

func TestTCPExchangePlan(t *testing.T) {
	x := &Xdperf{cfg: mixedConfig()}
	r := exchangeResponse(func(f *guest.TCPFlowVariant) {
		f.Close = "server"
		f.ResponseTimeoutMillis = 2500
		f.Flows[1] = guest.TCPFlow{Bytes: "0", ResponseBytes: "1000000"} // download, rounds nil = 1
		f.Flows[2] = guest.TCPFlow{Bytes: "4096"}                        // one-way flow in the same group
	})
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if !x.mixed.features.Exchange {
		t.Fatal("exchange feature not selected")
	}
	g := x.mixed.groups[0]
	if g.closeByServer != 1 || g.untilFin != 0 || g.respTimeoutMs != 2500 {
		t.Fatalf("group config %+v", g)
	}
	want := []tcpExchangeFlow{{true, 10000, 5}, {true, 1000000, 1}, {}, {true, 10000, 5}}
	if !reflect.DeepEqual(x.tcpExchange, want) {
		t.Fatalf("flows %+v, want %+v", x.tcpExchange, want)
	}
	if !reflect.DeepEqual(x.tcpVariantBytes, []uint64{100, 0, 4096, 100}) {
		t.Fatalf("request sizes %v", x.tcpVariantBytes)
	}
}

func TestTCPExchangeDefaults(t *testing.T) {
	x := &Xdperf{cfg: mixedConfig()}
	if err := x.prepareMixed(exchangeResponse(nil)); err != nil {
		t.Fatal(err)
	}
	g := x.mixed.groups[0]
	if g.closeByServer != 0 || g.respTimeoutMs != uint32(tcpDefaultResponseTimeout/time.Millisecond) {
		t.Fatalf("defaults %+v", g)
	}
	// Without any round field the plan is the one-way upload of before.
	x = &Xdperf{cfg: mixedConfig()}
	if err := x.prepareMixed(mixedResponse()); err != nil {
		t.Fatal(err)
	}
	if x.mixed.features.Exchange || x.mixed.groups[0].respTimeoutMs != 0 {
		t.Fatalf("one-way plan changed: %+v", x.mixed.groups[0])
	}
	if !reflect.DeepEqual(x.tcpExchange, make([]tcpExchangeFlow, 4)) {
		t.Fatalf("one-way flows have rounds: %+v", x.tcpExchange)
	}
}

func TestTCPExchangeUntilFin(t *testing.T) {
	x := &Xdperf{cfg: mixedConfig()}
	r := exchangeResponse(func(f *guest.TCPFlowVariant) {
		f.ResponseUntilFin = true
		for i := range f.Flows {
			f.Flows[i] = guest.TCPFlow{Bytes: "80"}
		}
	})
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if !x.mixed.features.Exchange || x.mixed.groups[0].untilFin != 1 || x.tcpExchange[0] != (tcpExchangeFlow{true, 0, 1}) {
		t.Fatalf("until_fin plan %+v %+v", x.mixed.groups[0], x.tcpExchange[0])
	}
}

func TestTCPExchangeRoundsUntilDuration(t *testing.T) {
	x := &Xdperf{cfg: mixedConfig()}
	x.cfg.Count, x.cfg.Duration = 0, time.Second
	r := exchangeResponse(func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0) })
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
	if x.tcpExchange[0] != (tcpExchangeFlow{true, 10000, 0}) {
		t.Fatalf("flow 0: %+v", x.tcpExchange[0])
	}
}

func TestTCPExchangeValidation(t *testing.T) {
	oneWay := func(f *guest.TCPFlowVariant) {
		for i := range f.Flows {
			f.Flows[i] = guest.TCPFlow{Bytes: "100"}
		}
	}
	for name, tc := range map[string]struct {
		mutate func(f *guest.TCPFlowVariant)
		cfg    func(x *Xdperf)
		tcp    bool // drop the packet variant (connections needs a single variant)
		want   string
	}{
		"rounds without response": {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0] = guest.TCPFlow{Bytes: "1", Rounds: u32p(2)} }, want: "rounds requires response_bytes"},
		"zero response":           {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].ResponseBytes = "0" }, want: "response_bytes must be above 0"},
		"bad response":            {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].ResponseBytes = "1k" }, want: "response_bytes"},
		"until_fin with response": {mutate: func(f *guest.TCPFlowVariant) { f.ResponseUntilFin = true }, want: "leave response_bytes and rounds unset"},
		"until_fin with rounds": {mutate: func(f *guest.TCPFlowVariant) {
			f.ResponseUntilFin = true
			oneWay(f)
			f.Flows[0].Rounds = u32p(1)
		}, want: "leave response_bytes and rounds unset"},
		"download rounds": {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Bytes = "0" }, want: "rounds must be 1"},
		"close value":     {mutate: func(f *guest.TCPFlowVariant) { f.Close = "peer" }, want: "close must be client or server"},
		"close without rounds": {mutate: func(f *guest.TCPFlowVariant) {
			oneWay(f)
			f.Close = "server"
		}, want: "require response_bytes or response_until_fin"},
		"timeout without rounds": {mutate: func(f *guest.TCPFlowVariant) {
			oneWay(f)
			f.ResponseTimeoutMillis = 1
		}, want: "require response_bytes or response_until_fin"},
		"rounds 0 unbounded": {
			mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0) },
			cfg:    func(x *Xdperf) { x.cfg.Count, x.cfg.Duration = 0, 0 },
			want:   "rounds 0 runs until --duration or --count",
		},
		"rounds 0 with close server": {
			mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0); f.Close = "server" },
			cfg:    func(x *Xdperf) { x.cfg.Count, x.cfg.Duration = 0, time.Second },
			want:   "rounds 0 has no last round",
		},
		"rounds 0 with connections": {
			mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0); f.Connections = u32p(8) },
			cfg:    func(x *Xdperf) { x.cfg.Count, x.cfg.Duration = 0, time.Second },
			tcp:    true,
			want:   "cannot be used with connections",
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := &Xdperf{cfg: mixedConfig()}
			if tc.cfg != nil {
				tc.cfg(x)
			}
			before := x.cfg
			r := exchangeResponse(tc.mutate)
			if tc.tcp {
				r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[1:]
			}
			err := x.prepareMixed(r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			if x.mixed != nil || !reflect.DeepEqual(before, x.cfg) {
				t.Fatal("partial mutation")
			}
		})
	}
	// The connections case is valid once rounds are finite.
	x := &Xdperf{cfg: mixedConfig()}
	x.cfg.Count, x.cfg.Duration = 0, time.Second
	r := exchangeResponse(func(f *guest.TCPFlowVariant) { f.Connections = u32p(8) })
	r.VariablePacketTemplate.Variants = r.VariablePacketTemplate.Variants[1:]
	if err := x.prepareMixed(r); err != nil {
		t.Fatal(err)
	}
}

func TestTCPRoundsError(t *testing.T) {
	for _, tc := range []struct {
		short, early uint64
		fail         bool
	}{{0, 0, false}, {1, 0, true}, {0, 1, true}, {2, 3, true}} {
		err := tcpRoundsError(coreelf.BpfTcpStats{ShortResponses: tc.short, PeerClosedEarly: tc.early})
		if (err != nil) != tc.fail {
			t.Fatalf("short %d early %d: %v", tc.short, tc.early, err)
		}
	}
}

// TestTCPFailedRunSummary checks that a run with failed flows or early peer
// closes still writes the summary, with the counters that explain the exit.
func TestTCPFailedRunSummary(t *testing.T) {
	stats, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 32, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()
	for _, tc := range []struct {
		name  string
		stats coreelf.BpfTcpStats
		key   string
		want  uint64
	}{
		{"none", coreelf.BpfTcpStats{Done: 4}, "", 0},
		{"timeout", coreelf.BpfTcpStats{Done: 3, Failed: 1, RespTimeouts: 1}, "response_timeouts", 1},
		{"short", coreelf.BpfTcpStats{Done: 4, ShortResponses: 2}, "short_responses", 2},
		{"early", coreelf.BpfTcpStats{Done: 4, PeerClosedEarly: 4}, "peer_closed_early", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "summary.json")
			x := &Xdperf{cfg: Config{SummaryJSON: path}, mixed: &mixedPlan{connections: 4},
				bpfobjs: &coreelf.BpfObjects{BpfMaps: coreelf.BpfMaps{TxStatsMap: stats, RxStatsMap: stats}}}
			x.beginSummary()
			s := tc.stats
			x.summary.TCP = &tcpSummary{Flows: 4, Done: s.Done, Failed: s.Failed, ResponseTimeouts: s.RespTimeouts,
				ShortResponses: s.ShortResponses, PeerClosedEarly: s.PeerClosedEarly}
			runErr := x.finishTCPRun(s)
			if (runErr != nil) != (tc.key != "") {
				t.Fatalf("error %v, want failure %v", runErr, tc.key != "")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("summary not written: %v", err)
			}
			var got struct {
				TCP map[string]any `json:"tcp"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if tc.key != "" && got.TCP[tc.key] != float64(tc.want) {
				t.Fatalf("%s = %v, want %d", tc.key, got.TCP[tc.key], tc.want)
			}
		})
	}
}

// TestTCPFailedRunSummaryWriteError keeps both errors when the summary write
// fails after flows failed.
func TestTCPFailedRunSummaryWriteError(t *testing.T) {
	stats, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 32, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()
	x := &Xdperf{cfg: Config{SummaryJSON: filepath.Join(t.TempDir(), "missing", "summary.json")}, mixed: &mixedPlan{connections: 4},
		bpfobjs: &coreelf.BpfObjects{BpfMaps: coreelf.BpfMaps{TxStatsMap: stats, RxStatsMap: stats}}}
	x.beginSummary()
	x.summary.TCP = &tcpSummary{Flows: 4, Done: 3, Failed: 1}
	err = x.finishTCPRun(coreelf.BpfTcpStats{Done: 3, Failed: 1})
	if err == nil || !strings.Contains(err.Error(), "1 of 4 flows failed") || !strings.Contains(err.Error(), "write summary JSON") {
		t.Fatalf("error %v, want the flow failure and the write failure", err)
	}
}

// TestTCPExchangeMapsBPF checks the per-flow targets and the per-group
// round settings in the maps BPF reads: tcp_flow_map and each template's cfg.
func TestTCPExchangeMapsBPF(t *testing.T) {
	resp := mixedResponse()
	a := resp.VariablePacketTemplate.Variants[1]
	a.Base = tcpTestBase(false, 0)
	fa := *a.TCPFlow
	fa.Close, fa.ResponseTimeoutMillis = "server", 1234
	fa.Flows = []guest.TCPFlow{{Bytes: "100", ResponseBytes: "7000", Rounds: u32p(3)}, {Bytes: "0", ResponseBytes: "9000"}, {Bytes: "500"}}
	a.TCPFlow = &fa
	b := a
	fb := fa
	fb.Close, fb.ResponseTimeoutMillis, fb.ResponseUntilFin = "", 0, true
	fb.Flows = []guest.TCPFlow{{Bytes: "80"}, {Bytes: "90"}}
	b.TCPFlow = &fb
	resp.VariablePacketTemplate.Variants = []guest.PacketVariant{a, b}

	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{cfg: mixedConfig(), Device: &net.Interface{MTU: 1500}, bpfSpec: spec, cpus: []int{0}, Logger: zap.NewNop()}
	if err := x.prepareMixed(resp); err != nil {
		t.Fatal(err)
	}
	x.bpfobjs = loadMixedTestObjects(t, x.mixed.features)
	target, err := parseTCPBase(a.Base)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.initTCPMaps(target, a.Base.Data); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		resp     uint64
		rounds   uint32
		bytes    uint64
		close    uint8
		untilFin uint8
		timeout  uint32
	}{
		{7000, 3, 100, 1, 0, 1234},
		{9000, 1, 0, 1, 0, 1234},
		{0, 0, 500, 1, 0, 1234},
		{0, 1, 80, 0, 1, uint32(tcpDefaultResponseTimeout / time.Millisecond)},
		{0, 1, 90, 0, 1, uint32(tcpDefaultResponseTimeout / time.Millisecond)},
	}
	templates := map[uint32]bool{}
	for i, w := range want {
		var f coreelf.BpfTcpFlow
		if err := x.bpfobjs.TcpFlowMap.Lookup(uint32(i), &f); err != nil {
			t.Fatal(err)
		}
		if f.RespTarget != w.resp || f.RoundsTarget != w.rounds || f.BytesTarget != w.bytes {
			t.Fatalf("flow %d: resp %d rounds %d bytes %d", i, f.RespTarget, f.RoundsTarget, f.BytesTarget)
		}
		var tmpl coreelf.BpfTcpTemplate
		if err := x.bpfobjs.TcpTemplateMap.Lookup(f.TemplateId, &tmpl); err != nil {
			t.Fatal(err)
		}
		templates[f.TemplateId] = true
		if tmpl.Cfg.CloseByServer != w.close || tmpl.Cfg.UntilFin != w.untilFin || tmpl.Cfg.RespTimeoutMs != w.timeout {
			t.Fatalf("flow %d template %d: close %d until_fin %d timeout %d", i, f.TemplateId,
				tmpl.Cfg.CloseByServer, tmpl.Cfg.UntilFin, tmpl.Cfg.RespTimeoutMs)
		}
	}
	if len(templates) != 2 {
		t.Fatalf("groups share a template: %v", templates)
	}
}
