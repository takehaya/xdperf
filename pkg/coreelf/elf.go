package coreelf

import (
	"fmt"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

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

func ReadCollection(constants map[string]interface{}) (*BpfObjects, error) {
	// Remove memory limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %w", err)
	}

	objs := &BpfObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("fail to load bpf spec: %w", err)
	}
	for name, value := range constants {
		varSpec, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("constant %s not found in spec", name)
		}
		if err := varSpec.Set(value); err != nil {
			return nil, err
		}
	}
	err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1073741823, LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, fmt.Errorf("fail to load and assign bpf objects: %w", err)
	}
	return objs, nil
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
