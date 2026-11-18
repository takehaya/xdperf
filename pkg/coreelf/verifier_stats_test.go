package coreelf

import (
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

// Spike S1: record how many instructions the verifier processes for each
// mixed specialization, to see how much headroom the 1M limit leaves.
func TestBpfMixedVerifierStats(t *testing.T) {
	cases := map[string]MixedProgramFeatures{
		"bare":                 {},
		"nested":               {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true},
		"timestamps-payload":   {Timestamps: true, Payload: true},
		"nested-extensions":    {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Timestamps: true, Payload: true, TemplateEntries: 18},
		"x-bare":               {Exchange: true},
		"x-nested":             {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Exchange: true},
		"x-timestamps-payload": {Timestamps: true, Payload: true, Exchange: true},
		"x-nested-extensions":  {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Timestamps: true, Payload: true, TemplateEntries: 18, Exchange: true},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		objs, spec, err := ReadBaseCollectionWithSizes(defaultConsts(), map[string]uint32{"diff_map": 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := LoadMixedProgramsWithFeatures(objs, spec, cases[name]); err != nil {
			objs.Close()
			t.Fatalf("%s: %v", name, err)
		}
		for _, p := range []struct {
			name string
			prog *ebpf.Program
		}{
			{"tx_mixed", objs.XdpTxMixed}, {"tx_tcp", objs.XdpTxTcpMixed},
			{"rx_mixed", objs.XdpRxMixed}, {"rx_tcp", objs.XdpRxTcpMixed},
		} {
			info, err := p.prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			n, _ := info.VerifiedInstructions()
			t.Logf("VSTAT %s %s %d", name, p.name, n)
		}
		objs.Close()
	}
}
