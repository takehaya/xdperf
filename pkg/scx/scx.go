package scx

// The sched_ext scheduler object (src/scx_prog.c) is compiled through the
// same Docker pipeline as the data plane: `make bpf-gen` runs both this
// directive and the one in pkg/coreelf.
//
// -no-global-types: struct sched_ext_ops holds function pointers, which have
// no Go representation; the loader defines the value types it needs by hand.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc $BPF_CLANG -cflags $BPF_CFLAGS Scx ../../src/scx_prog.c -- -I /usr/include/x86_64-linux-gnu
