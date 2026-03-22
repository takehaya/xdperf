package coreelf

import (
	"errors"
	"fmt"
	"strings"
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
		return nil, nil, fmt.Errorf("fail to load bpf objects: %w", loadWithVerifierLog(spec, objs, debugMode))
	}

	// Populate the prog_array for tail calls
	// xdp_tx tail-calls to xdp_tx_checksum at index 0
	if objs.XdpProgs != nil && objs.XdpTxChecksum != nil {
		checksumProgFD := uint32(objs.XdpTxChecksum.FD())
		if err := objs.XdpProgs.Put(uint32(0), checksumProgFD); err != nil {
			objs.Close()
			return nil, nil, fmt.Errorf("fail to populate xdp_progs map: %w", err)
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
func loadWithVerifierLog(spec *ebpf.CollectionSpec, objs *BpfObjects, debugMode bool) error {
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
	if debugMode {
		fmt.Printf("%+v\n", verr)
		return err
	}
	log := fmt.Sprintf("%+v", verr)
	lines := strings.Split(log, "\n")
	const tailLines = 50
	if len(lines) > tailLines {
		fmt.Printf("... (%d lines truncated, use --debugmode for full log)\n", len(lines)-tailLines)
		lines = lines[len(lines)-tailLines:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	return err
}
