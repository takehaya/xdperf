package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

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
