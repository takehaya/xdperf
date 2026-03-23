package coreelf

import (
	"errors"
	"fmt"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// MaxPacketEntry is the maximum number of entries for tx_override_map.
// This must match MAX_PACKET_ENTRY in src/xdp_prog.h.
const MaxPacketEntry uint32 = 1 << 25 // 33554432
const MinPacketEntry uint32 = 1

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

func ReadCollection(constants map[string]any, mapSize uint32, diffMapSize uint32, debug ...bool) (*BpfObjects, *ebpf.CollectionSpec, error) {
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

	// Dynamically set tx_override_map size before loading
	if mapSpec, ok := spec.Maps["tx_override_map"]; ok {
		if mapSize > 0 && mapSize <= MaxPacketEntry {
			mapSpec.MaxEntries = mapSize
		}
	}

	// Dynamically set diff_map size before loading
	if mapSpec, ok := spec.Maps["diff_map"]; ok {
		if diffMapSize > 0 {
			mapSpec.MaxEntries = diffMapSize
		}
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
	err = spec.LoadAndAssign(objs, nil)
	if err != nil {
		if debugMode {
			// Retry with verbose verifier log (expensive — can OOM in small VMs)
			return nil, nil, fmt.Errorf("fail to load bpf objects: %w", loadWithVerifierLog(spec, objs))
		}
		return nil, nil, fmt.Errorf("fail to load bpf objects: %w", err)
	}

	// Populate the prog_array for tail calls
	// Index 0: xdp_tx_checksum (len_changed path)
	// Index 1: xdp_tx_csum_diff (incremental checksum path)
	if objs.XdpProgs != nil {
		if objs.XdpTxChecksum == nil {
			objs.Close()
			return nil, nil, fmt.Errorf("xdp_tx_checksum program is missing but xdp_progs map exists")
		}
		if objs.XdpTxCsumDiff == nil {
			objs.Close()
			return nil, nil, fmt.Errorf("xdp_tx_csum_diff program is missing but xdp_progs map exists")
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
func loadWithVerifierLog(spec *ebpf.CollectionSpec, objs *BpfObjects) error {
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
