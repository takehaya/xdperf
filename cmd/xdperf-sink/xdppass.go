package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	xdpPassMu   sync.Mutex
	xdpPassLink link.Link
	xdpPassProg *ebpf.Program
)

// attachXDPPass loads a two-instruction "return XDP_PASS" program (built from
// BPF assembly, no C toolchain needed) and attaches it to dev. It falls back
// to generic mode when the driver refuses a native attach.
func attachXDPPass(dev string) error {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "xdp_pass_sink",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		return fmt.Errorf("load program: %w", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: link.XDPGenericMode})
		if err != nil {
			prog.Close()
			return fmt.Errorf("attach: %w", err)
		}
	}
	xdpPassMu.Lock()
	xdpPassLink, xdpPassProg = l, prog
	xdpPassMu.Unlock()
	return nil
}

func detachXDPPass() {
	xdpPassMu.Lock()
	defer xdpPassMu.Unlock()
	if xdpPassLink != nil {
		xdpPassLink.Close()
		xdpPassLink = nil
	}
	if xdpPassProg != nil {
		xdpPassProg.Close()
		xdpPassProg = nil
	}
}
