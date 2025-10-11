package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../src/xdp_prog.c -- -I ./src -I /usr/include/x86_64-linux-gnu

func ReadCollection(possibleCpu int) (*bpfObjects, error) {
	objs := &bpfObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("fail to load bpf spec: %w", err)
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
