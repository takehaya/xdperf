package coreelf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func defaultConsts() map[string]any {
	return map[string]any{
		"swap_resp": uint32(0),
	}
}

func loadOrFail(t *testing.T, consts map[string]any) (*BpfObjects, *ebpf.CollectionSpec) {
	t.Helper()
	objs, spec, err := ReadCollection(consts, 1)
	if err != nil {
		// Print the full verifier log (branch-level, captured by cilium/ebpf on error).
		// %+v avoids the default truncation so CI output is actionable.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("ReadCollection failed: %+v", ve)
		}
		t.Fatalf("ReadCollection failed: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return objs, spec
}

// TestBpfProgramsLoad verifies that all XDP programs pass the BPF verifier.
func TestBpfProgramsLoad(t *testing.T) {
	objs, _ := loadOrFail(t, defaultConsts())

	for _, p := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"xdp_tx", objs.XdpTx},
		{"xdp_tx_checksum", objs.XdpTxChecksum},
		{"xdp_tx_csum_diff", objs.XdpTxCsumDiff},
		{"xdp_tx_csum_recalc", objs.XdpTxCsumRecalc},
		{"xdp_rx", objs.XdpRx},
		{"xdp_pass_dummy", objs.XdpPassDummy},
		{"xdp_tx_tcp", objs.XdpTxTcp},
		{"xdp_rx_tcp", objs.XdpRxTcp},
		{"xdp_rx_tcp_server", objs.XdpRxTcpServer},
	} {
		if p.prog == nil {
			t.Errorf("program %s is nil", p.name)
		}
	}
}

// TestBpfProgramsLoadVariants verifies loading with different constant combinations.
func TestBpfProgramsLoadVariants(t *testing.T) {
	for name, consts := range map[string]map[string]any{
		"swap_resp=0": {"swap_resp": uint32(0)},
		"swap_resp=1": {"swap_resp": uint32(1)},
	} {
		t.Run(name, func(t *testing.T) {
			loadOrFail(t, consts)
		})
	}
}

// TestBpfTailCallSetup verifies the tail call prog_array is populated.
func TestBpfTailCallSetup(t *testing.T) {
	objs, _ := loadOrFail(t, defaultConsts())

	// All three tail-call slots must be populated, else the len_changed /
	// !len_changed paths abort at runtime:
	//   0: xdp_tx_checksum, 1: xdp_tx_csum_diff, 2: xdp_tx_csum_recalc
	for _, slot := range []struct {
		idx  uint32
		name string
	}{
		{0, "xdp_tx_checksum"},
		{1, "xdp_tx_csum_diff"},
		{2, "xdp_tx_csum_recalc"},
	} {
		var progFD uint32
		if err := objs.XdpProgs.Lookup(slot.idx, &progFD); err != nil {
			t.Fatalf("prog_array[%d] (%s) lookup failed: %v", slot.idx, slot.name, err)
		}
		if progFD == 0 {
			t.Errorf("prog_array[%d] (%s) is empty", slot.idx, slot.name)
		}
	}
}

// TestBpfDummyProgramLoad verifies the lightweight dummy program load path.
func TestBpfDummyProgramLoad(t *testing.T) {
	prog, cleanup, err := LoadDummyProgram()
	if err != nil {
		t.Fatalf("LoadDummyProgram failed: %v", err)
	}
	defer cleanup()

	if prog == nil {
		t.Fatal("returned nil program")
	}
}

// TestBpfVariablesReadable verifies BPF spec variables can be read after load.
func TestBpfVariablesReadable(t *testing.T) {
	_, spec := loadOrFail(t, defaultConsts())

	for _, name := range []string{
		"max_packet_size",
		"max_diffs_per_packet",
		"max_base_packets",
		"max_checksum_entries",
		"min_packet_size",
	} {
		varSpec, ok := spec.Variables[name]
		if !ok {
			t.Errorf("variable %s not found", name)
			continue
		}
		var val uint32
		if err := varSpec.Get(&val); err != nil {
			t.Errorf("variable %s: %v", name, err)
		}
	}
}

// Ordinary startup must not verify mixed programs, but loading them later must
// share the already initialized flow map and populate the same tail-call map.
func TestBpfDeferredMixedLoad(t *testing.T) {
	objs, spec, err := ReadBaseCollectionWithSizes(defaultConsts(), map[string]uint32{"diff_map": 1})
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	if objs.XdpTxMixed != nil || objs.XdpRxTcpMixed != nil {
		t.Fatal("mixed programs loaded during base startup")
	}
	flowInfo, err := objs.TcpFlowMap.Info()
	if err != nil {
		t.Fatal(err)
	}
	flowID, _ := flowInfo.ID()
	if err := LoadMixedPrograms(objs, spec); err != nil {
		t.Fatal(err)
	}
	info, err := objs.XdpTxTcpMixed.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := info.MapIDs()
	if !ok {
		t.Fatal("missing program map IDs")
	}
	shared := false
	for _, id := range ids {
		if id == flowID {
			shared = true
		}
	}
	if !shared {
		t.Fatal("deferred TCP program uses a different flow map")
	}
	for i := uint32(0); i < 4; i++ {
		var id uint32
		if err := objs.MixedProgs.Lookup(i, &id); err != nil || id == 0 {
			t.Fatalf("mixed tail call %d: id=%d err=%v", i, id, err)
		}
	}
	if err := LoadMixedPrograms(objs, spec); err != nil {
		t.Fatal(err)
	}
}

// These are independently verified on every kernel in the BPF CI matrix.
func TestBpfMixedSpecializations(t *testing.T) {
	for name, features := range map[string]MixedProgramFeatures{
		"bare":     {},
		"udp-zero": {Lengths: 2, OuterIPs: 1, UDPs: 1},
		"udp-lco":  {Lengths: 2, OuterIPs: 1, UDPs: 1, LCO: true},
		"nested":   {Lengths: 4, OuterIPs: 2, UDPs: 2, LCO: true},
	} {
		t.Run(name, func(t *testing.T) {
			objs, spec, err := ReadBaseCollectionWithSizes(defaultConsts(), map[string]uint32{"diff_map": 1})
			if err != nil {
				t.Fatal(err)
			}
			defer objs.Close()
			if err := LoadMixedProgramsWithFeatures(objs, spec, features); err != nil {
				t.Fatal(err)
			}
			var original uint32
			if err := spec.Variables["mixed_max_udps"].Get(&original); err != nil {
				t.Fatal(err)
			}
			if original != 4 {
				t.Fatalf("original spec was mutated: %d", original)
			}
			for i, want := range []*ebpf.Program{objs.XdpTx, objs.XdpTxTcpMixed, objs.XdpRxTcpMixed, objs.XdpRx} {
				var got uint32
				if err := objs.MixedProgs.Lookup(uint32(i), &got); err != nil {
					t.Fatal(err)
				}
				info, err := want.Info()
				if err != nil {
					t.Fatal(err)
				}
				id, _ := info.ID()
				if got != uint32(id) {
					t.Fatalf("tail call %d: %d, want %d", i, got, id)
				}
			}
		})
	}
}
