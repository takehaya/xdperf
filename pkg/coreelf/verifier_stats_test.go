package coreelf

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

var vstatCases = map[string]MixedProgramFeatures{
	"bare":                 {},
	"nested":               {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true},
	"timestamps-payload":   {Timestamps: true, Payload: true},
	"nested-extensions":    {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Timestamps: true, Payload: true, TemplateEntries: 18},
	"x-bare":               {Exchange: true},
	"x-nested":             {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Exchange: true},
	"x-timestamps-payload": {Timestamps: true, Payload: true, Exchange: true},
	"x-nested-extensions":  {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true, Timestamps: true, Payload: true, TemplateEntries: 18, Exchange: true},
	// spike-only splits
	"timestamps":   {Timestamps: true},
	"payload":      {Payload: true},
	"max":          {Lengths: 8, OuterIPs: 4, UDPs: 4, LCO: true, Timestamps: true, Payload: true},
	"x-max":        {Lengths: 8, OuterIPs: 4, UDPs: 4, LCO: true, Timestamps: true, Payload: true, Exchange: true},
	"x-timestamps": {Timestamps: true, Exchange: true},
	"x-payload":    {Payload: true, Exchange: true},
}

func vstatNames() []string {
	if env := os.Getenv("VSTAT_CASES"); env != "" {
		return strings.Split(env, ",")
	}
	return []string{"bare", "nested", "timestamps-payload", "nested-extensions", "x-bare", "x-nested", "x-timestamps-payload", "x-nested-extensions"}
}

// Spike S1: record how many instructions the verifier processes for each
// mixed specialization, to see how much headroom the 1M limit leaves.
// VSTAT_CASES=a,b selects cases; VPROF=tx_tcp|rx_tcp prints a per-instruction
// visit histogram from the verifier log (VPROF/VSRC lines).
func TestBpfMixedVerifierStats(t *testing.T) {
	prof := os.Getenv("VPROF")
	if prof != "" {
		spikeLogLevel = ebpf.LogLevelInstruction
		spikeLogSize = 1<<30 - 1
		defer func() { spikeLogLevel, spikeLogSize = 0, 0 }()
	}
	for _, name := range vstatNames() {
		features, ok := vstatCases[name]
		if !ok {
			t.Fatalf("unknown case %s", name)
		}
		objs, spec, err := ReadBaseCollectionWithSizes(defaultConsts(), map[string]uint32{"diff_map": 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := LoadMixedProgramsWithFeatures(objs, spec, features); err != nil {
			objs.Close()
			t.Logf("VSTAT %s LOADFAIL %.300v", name, err)
			t.Fail()
			continue
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
			scan, _ := MixedTxScan()
			t.Logf("VSTAT %s %s %d scan=%d", name, p.name, n, scan)
			if prof == p.name {
				vprof(name, p.prog.VerifierLog)
			}
		}
		objs.Close()
	}
}

var vprofInsn = regexp.MustCompile(`^(\d+): \(`)

func vprof(name, log string) {
	fmt.Printf("VLOGLEN %s %d\n", name, len(log))
	counts := map[int]int{}
	src := map[int]string{}
	last := ""
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "func#") || strings.HasPrefix(line, "processed ") || strings.HasPrefix(line, "Func#") {
			fmt.Printf("VFUNC %s %s\n", name, line)
			continue
		}
		if strings.HasPrefix(line, "; ") {
			last = line
			continue
		}
		m := vprofInsn.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		counts[idx]++
		if last != "" {
			if _, ok := src[idx]; !ok {
				src[idx] = last
			}
			last = ""
		}
	}
	idxs := make([]int, 0, len(counts))
	for i := range counts {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	var b strings.Builder
	for _, i := range idxs {
		fmt.Fprintf(&b, "VPROF %s %d %d\n", name, i, counts[i])
		if s, ok := src[i]; ok {
			fmt.Fprintf(&b, "VSRC %s %d %s\n", name, i, s)
		}
	}
	fmt.Print(b.String())
}
