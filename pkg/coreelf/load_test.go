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
