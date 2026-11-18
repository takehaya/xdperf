package xdperf

import (
	"testing"
	"time"

	"github.com/takehaya/xdperf/pkg/guest"
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
	want := []tcpExchangeFlow{{10000, 5}, {1000000, 1}, {0, 0}, {10000, 5}}
	for i, w := range want {
		if x.tcpExchange[i] != w {
			t.Fatalf("flow %d: %+v, want %+v", i, x.tcpExchange[i], w)
		}
	}
	if x.tcpVariantBytes[0] != 100 || x.tcpVariantBytes[1] != 0 || x.tcpVariantBytes[2] != 4096 {
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
	for _, e := range x.tcpExchange {
		if e != (tcpExchangeFlow{}) {
			t.Fatalf("one-way flow has rounds: %+v", e)
		}
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
	if !x.mixed.features.Exchange || x.mixed.groups[0].untilFin != 1 || x.tcpExchange[0] != (tcpExchangeFlow{0, 1}) {
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
	if x.tcpExchange[0] != (tcpExchangeFlow{10000, 0}) {
		t.Fatalf("flow 0: %+v", x.tcpExchange[0])
	}
}

func TestTCPExchangeValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(f *guest.TCPFlowVariant)
		cfg    func(x *Xdperf)
	}{
		"rounds without response": {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0] = guest.TCPFlow{Bytes: "1", Rounds: u32p(2)} }},
		"zero response":           {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].ResponseBytes = "0" }},
		"bad response":            {mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].ResponseBytes = "1k" }},
		"until_fin with response": {mutate: func(f *guest.TCPFlowVariant) { f.ResponseUntilFin = true }},
		"close value":             {mutate: func(f *guest.TCPFlowVariant) { f.Close = "peer" }},
		"close without rounds": {mutate: func(f *guest.TCPFlowVariant) {
			f.Close = "server"
			for i := range f.Flows {
				f.Flows[i] = guest.TCPFlow{Bytes: "100"}
			}
		}},
		"timeout without rounds": {mutate: func(f *guest.TCPFlowVariant) {
			f.ResponseTimeoutMillis = 1
			for i := range f.Flows {
				f.Flows[i] = guest.TCPFlow{Bytes: "100"}
			}
		}},
		"rounds 0 unbounded": {
			mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0) },
			cfg:    func(x *Xdperf) { x.cfg.Count, x.cfg.Duration = 0, 0 },
		},
		"rounds 0 with connections": {
			mutate: func(f *guest.TCPFlowVariant) { f.Flows[0].Rounds = u32p(0); f.Connections = u32p(8) },
			cfg:    func(x *Xdperf) { x.cfg.Count, x.cfg.Duration = 0, time.Second },
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := &Xdperf{cfg: mixedConfig()}
			if tc.cfg != nil {
				tc.cfg(x)
			}
			if err := x.prepareMixed(exchangeResponse(tc.mutate)); err == nil {
				t.Fatal("accepted invalid input")
			}
			if x.mixed != nil {
				t.Fatal("partial mutation")
			}
		})
	}
}
