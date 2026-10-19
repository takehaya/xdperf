package coreelf

import (
	"errors"
	"fmt"
	"reflect"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// MaxDiffEntries is the maximum number of diff entries per CPU. This MUST match
// MAX_DIFF_ENTRIES in src/xdp_packet.h: the data plane hard-caps the per-CPU
// round-robin pool to this value (see the clamp in src/xdp_prog.c), so sizing
// diff_map beyond it would silently waste entries the kernel never reads.
const MaxDiffEntries uint32 = 131072

// XdpMd is the XDP metadata structure for BPF_PROG_RUN.
// This structure must match the kernel's xdp_md structure.
type XdpMd struct {
	_              structs.HostLayout
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS Bpf ../../src/xdp_prog.c -- -I ./src -I /usr/include/x86_64-linux-gnu

// ReadCollection loads the BPF objects with diff_map sized to diffMapSize.
// See ReadCollectionWithSizes for the general form.
func ReadCollection(constants map[string]any, diffMapSize uint32, debug ...bool) (*BpfObjects, *ebpf.CollectionSpec, error) {
	return ReadCollectionWithSizes(constants, map[string]uint32{"diff_map": diffMapSize}, debug...)
}

// ReadCollectionWithSizes loads the BPF objects, overriding max_entries of the
// maps named in sizes before load (0 keeps the compiled-in size). diff_map is
// clamped to MaxDiffEntries. Known resizable maps:
//   - diff_map          per-CPU diff pool of the replay client
//   - tcp_srv_flow_map  flow table of --tcp-server (LRU hash; 1 in other modes)
func ReadCollectionWithSizes(constants map[string]any, sizes map[string]uint32, debug ...bool) (*BpfObjects, *ebpf.CollectionSpec, error) {
	return readCollection(constants, sizes, true, debug...)
}

// ReadBaseCollectionWithSizes defers mixed TCP programs until the plugin returns
// a mixed variant set. Ordinary packet and standalone TCP startup avoid their
// verifier cost. ReadCollectionWithSizes still loads everything for load tests.
func ReadBaseCollectionWithSizes(constants map[string]any, sizes map[string]uint32, debug ...bool) (*BpfObjects, *ebpf.CollectionSpec, error) {
	return readCollection(constants, sizes, false, debug...)
}

func readCollection(constants map[string]any, sizes map[string]uint32, mixed bool, debug ...bool) (*BpfObjects, *ebpf.CollectionSpec, error) {
	debugMode := len(debug) > 0 && debug[0]
	// Remove memory limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove memory limit: %w", err)
	}

	objs := &BpfObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	spec, err := LoadBpf()
	if err != nil {
		return nil, nil, fmt.Errorf("fail to load bpf spec: %w", err)
	}

	// Dynamically size maps before loading. diff_map is clamped to the
	// data-plane cap (MaxDiffEntries) so the control plane never sizes it
	// beyond what the kernel round-robin will actually read.
	for name, n := range sizes {
		mapSpec, ok := spec.Maps[name]
		if !ok || n == 0 {
			continue
		}
		if name == "diff_map" && n > MaxDiffEntries {
			n = MaxDiffEntries
		}
		mapSpec.MaxEntries = n
	}

	for name, value := range constants {
		varSpec, ok := spec.Variables[name]
		if !ok {
			return nil, nil, fmt.Errorf("constant %s not found in spec", name)
		}
		if err := varSpec.Set(value); err != nil {
			return nil, nil, err
		}
	}
	var target any = objs
	var base baseObjects
	if !mixed {
		target = &base
	}
	err = spec.LoadAndAssign(target, nil)
	if err != nil {
		if debugMode {
			// Retry with verbose verifier log (expensive — can OOM in small VMs)
			return nil, nil, fmt.Errorf("fail to load bpf objects: %w", loadWithVerifierLog(spec, target))
		}
		return nil, nil, fmt.Errorf("fail to load bpf objects: %w", err)
	}

	if !mixed {
		objs.BpfMaps, objs.BpfVariables = base.BpfMaps, base.BpfVariables
		objs.XdpPassDummy, objs.XdpRx, objs.XdpRxTcp, objs.XdpRxTcpServer = base.XdpPassDummy, base.XdpRx, base.XdpRxTcp, base.XdpRxTcpServer
		objs.XdpTx, objs.XdpTxChecksum, objs.XdpTxCsumDiff, objs.XdpTxCsumRecalc, objs.XdpTxTcp = base.XdpTx, base.XdpTxChecksum, base.XdpTxCsumDiff, base.XdpTxCsumRecalc, base.XdpTxTcp
	}

	// Populate the prog_array for tail calls
	// Index 0: xdp_tx_checksum (len_changed dispatch + packet length update)
	// Index 1: xdp_tx_csum_diff (incremental checksum path, !len_changed)
	// Index 2: xdp_tx_csum_recalc (full checksum recalculation, len_changed)
	if objs.XdpProgs == nil {
		objs.Close()
		return nil, nil, fmt.Errorf("xdp_progs map is missing from BPF objects")
	}
	if objs.XdpTxChecksum == nil {
		objs.Close()
		return nil, nil, fmt.Errorf("xdp_tx_checksum program is missing from BPF objects")
	}
	if objs.XdpTxCsumDiff == nil {
		objs.Close()
		return nil, nil, fmt.Errorf("xdp_tx_csum_diff program is missing from BPF objects")
	}
	if objs.XdpTxCsumRecalc == nil {
		objs.Close()
		return nil, nil, fmt.Errorf("xdp_tx_csum_recalc program is missing from BPF objects")
	}
	checksumProgFD := uint32(objs.XdpTxChecksum.FD())
	if err := objs.XdpProgs.Put(uint32(0), checksumProgFD); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("fail to populate xdp_progs[0] (xdp_tx_checksum): %w", err)
	}
	csumDiffProgFD := uint32(objs.XdpTxCsumDiff.FD())
	if err := objs.XdpProgs.Put(uint32(1), csumDiffProgFD); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("fail to populate xdp_progs[1] (xdp_tx_csum_diff): %w", err)
	}
	csumRecalcProgFD := uint32(objs.XdpTxCsumRecalc.FD())
	if err := objs.XdpProgs.Put(uint32(2), csumRecalcProgFD); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("fail to populate xdp_progs[2] (xdp_tx_csum_recalc): %w", err)
	}

	if mixed {
		if err := populateMixedPrograms(objs); err != nil {
			objs.Close()
			return nil, nil, err
		}
	}

	return objs, spec, nil
}

// LoadDummyProgram loads only the xdp_pass_dummy program for lightweight probing.
// This is much faster than ReadCollection as it doesn't create the large maps.
func LoadDummyProgram() (*ebpf.Program, func(), error) {
	// Remove memory limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove memory limit: %w", err)
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, nil, fmt.Errorf("fail to load bpf spec: %w", err)
	}

	// Set required constant
	if varSpec, ok := spec.Variables["swap_resp"]; ok {
		if err := varSpec.Set(uint32(0)); err != nil {
			return nil, nil, fmt.Errorf("fail to set swap_resp: %w", err)
		}
	}

	// Load only the dummy program
	progSpec := spec.Programs["xdp_pass_dummy"]
	if progSpec == nil {
		return nil, nil, fmt.Errorf("xdp_pass_dummy program not found")
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to load xdp_pass_dummy: %w", err)
	}

	cleanup := func() {
		prog.Close()
	}

	return prog, cleanup, nil
}

// loadWithVerifierLog retries loading with verbose verifier log and returns the error.
// Only called in debug mode — instruction-level verifier logging is expensive and
// can OOM in memory-constrained CI VMs (especially on older kernels like 6.1).
func loadWithVerifierLog(spec *ebpf.CollectionSpec, objs any) error {
	err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1 << 30, LogLevel: ebpf.LogLevelInstruction},
	})
	if err == nil {
		return nil
	}
	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) {
		return err
	}
	fmt.Printf("%+v\n", verr)
	return err
}

// Only the programs needed before a plugin selects mixed mode are assigned.
// Maps remain shared with programs loaded later.
type baseObjects struct {
	BpfMaps
	BpfVariables
	XdpPassDummy    *ebpf.Program `ebpf:"xdp_pass_dummy"`
	XdpRx           *ebpf.Program `ebpf:"xdp_rx"`
	XdpRxTcp        *ebpf.Program `ebpf:"xdp_rx_tcp"`
	XdpRxTcpServer  *ebpf.Program `ebpf:"xdp_rx_tcp_server"`
	XdpTx           *ebpf.Program `ebpf:"xdp_tx"`
	XdpTxChecksum   *ebpf.Program `ebpf:"xdp_tx_checksum"`
	XdpTxCsumDiff   *ebpf.Program `ebpf:"xdp_tx_csum_diff"`
	XdpTxCsumRecalc *ebpf.Program `ebpf:"xdp_tx_csum_recalc"`
	XdpTxTcp        *ebpf.Program `ebpf:"xdp_tx_tcp"`
}

// LoadMixedPrograms adds mixed dispatch/TCP programs to an existing collection.
// Reusing every named map preserves configuration, flow state and tail calls.
func LoadMixedPrograms(objs *BpfObjects, spec *ebpf.CollectionSpec) error {
	if objs.XdpTxMixed != nil {
		return nil
	}
	replacements := make(map[string]*ebpf.Map)
	maps := reflect.ValueOf(objs.BpfMaps)
	for i := 0; i < maps.NumField(); i++ {
		name := maps.Type().Field(i).Tag.Get("ebpf")
		if m, ok := maps.Field(i).Interface().(*ebpf.Map); ok && m != nil {
			replacements[name] = m
		}
	}
	var mixed struct {
		XdpRxMixed    *ebpf.Program `ebpf:"xdp_rx_mixed"`
		XdpRxTcpMixed *ebpf.Program `ebpf:"xdp_rx_tcp_mixed"`
		XdpTxMixed    *ebpf.Program `ebpf:"xdp_tx_mixed"`
		XdpTxTcpMixed *ebpf.Program `ebpf:"xdp_tx_tcp_mixed"`
	}
	if err := spec.LoadAndAssign(&mixed, &ebpf.CollectionOptions{MapReplacements: replacements}); err != nil {
		return fmt.Errorf("load mixed programs: %w", err)
	}
	objs.XdpRxMixed, objs.XdpRxTcpMixed = mixed.XdpRxMixed, mixed.XdpRxTcpMixed
	objs.XdpTxMixed, objs.XdpTxTcpMixed = mixed.XdpTxMixed, mixed.XdpTxTcpMixed
	return populateMixedPrograms(objs)
}

func populateMixedPrograms(objs *BpfObjects) error {
	for i, prog := range []*ebpf.Program{objs.XdpTx, objs.XdpTxTcpMixed, objs.XdpRxTcpMixed, objs.XdpRx} {
		if err := objs.MixedProgs.Put(uint32(i), uint32(prog.FD())); err != nil {
			return fmt.Errorf("mixed tail call %d: %w", i, err)
		}
	}
	return nil
}
