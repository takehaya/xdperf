package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	nkFastpathMu    sync.Mutex
	nkFastpathLinks []link.Link
	nkFastpathProgs []*ebpf.Program
)

const (
	skbProtocolOffset = 16 // offsetof(struct __sk_buff, protocol)
	skbDataOffset     = 76 // offsetof(struct __sk_buff, data)
	skbDataEndOffset  = 80 // offsetof(struct __sk_buff, data_end)
	ethHLen           = 14
	ipv4HLen          = 20
	ethProtoOffset    = 12
	ipv4DaddrOffset   = 30 // 14 (eth) + 16 (offsetof(struct iphdr, daddr))
)

// attachNetkitFastpath attaches a minimal Cilium-style BPF redirect fastpath
// on a router/host namespace bridging an ingress device (e.g. veth/NIC) and a
// primary netkit device:
//   - TCX ingress on ingressDev: IPv4 packets to podIP -> bpf_redirect_peer(netkitPrimaryIfindex, 0)
//   - Netkit peer on netkitPrimaryDev: IPv4 packets from the Pod -> bpf_redirect_neigh(ingressIfindex, NULL, 0, 0)
//
// Format of spec: "<ingress-dev>:<netkit-primary-dev>:<pod-ipv4>"
func attachNetkitFastpath(spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("invalid -netkit-fastpath %q (expected <ingress-dev>:<netkit-primary-dev>:<pod-ipv4>)", spec)
	}
	inDev, err := net.InterfaceByName(parts[0])
	if err != nil {
		return fmt.Errorf("ingress device %s: %w", parts[0], err)
	}
	nkDev, err := net.InterfaceByName(parts[1])
	if err != nil {
		return fmt.Errorf("netkit device %s: %w", parts[1], err)
	}
	ip := net.ParseIP(parts[2]).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address %q", parts[2])
	}
	ethPIP := int32(binary.NativeEndian.Uint16([]byte{0x08, 0x00}))
	podIP := int32(binary.NativeEndian.Uint32(ip))

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// 1. TCX ingress program on inDev -> bpf_redirect_peer(nkDev.Index, 0)
	// Use 32-bit JNE.Imm32 comparisons because LoadMem (Word/Half) zero-extends
	// into 64-bit registers while 64-bit JNE.Imm sign-extends int32 immediates
	// (which would mismatch any IPv4 address whose high bit in native order is 1,
	// e.g. last octet >= 128 on little-endian).
	tcxProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "tcx_to_netkit",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R3, asm.R1, skbDataEndOffset, asm.Word),
			asm.Mov.Reg(asm.R4, asm.R2),
			asm.Add.Imm(asm.R4, ethHLen+ipv4HLen),
			asm.JGT.Reg(asm.R4, asm.R3, "pass"),
			asm.LoadMem(asm.R5, asm.R2, ethProtoOffset, asm.Half),
			asm.JNE.Imm32(asm.R5, ethPIP, "pass"),
			asm.LoadMem(asm.R5, asm.R2, ipv4DaddrOffset, asm.Word),
			asm.JNE.Imm32(asm.R5, podIP, "pass"),
			asm.Mov.Imm(asm.R1, int32(nkDev.Index)),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRedirectPeer.Call(),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // TC_ACT_OK
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return fmt.Errorf("load tcx_to_netkit: %w", err)
	}

	// 2. Netkit peer program on nkDev -> bpf_redirect_neigh(inDev.Index, NULL, 0, 0)
	// Checks skb->protocol so it works identically in both L2 and L3 netkit modes.
	nkProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "nk_from_pod",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, skbProtocolOffset, asm.Word),
			asm.JNE.Imm32(asm.R2, ethPIP, "pass"),
			asm.Mov.Imm(asm.R1, int32(inDev.Index)),
			asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Imm(asm.R3, 0),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnRedirectNeigh.Call(),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // NETKIT_PASS
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		tcxProg.Close()
		return fmt.Errorf("load nk_from_pod: %w", err)
	}

	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Interface: inDev.Index,
		Program:   tcxProg,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		tcxProg.Close()
		nkProg.Close()
		return fmt.Errorf("attach TCX ingress on %s: %w", inDev.Name, err)
	}

	nkLink, err := link.AttachNetkit(link.NetkitOptions{
		Interface: nkDev.Index,
		Program:   nkProg,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		tcxLink.Close()
		tcxProg.Close()
		nkProg.Close()
		return fmt.Errorf("attach netkit peer on %s: %w", nkDev.Name, err)
	}

	nkFastpathMu.Lock()
	nkFastpathLinks = []link.Link{tcxLink, nkLink}
	nkFastpathProgs = []*ebpf.Program{tcxProg, nkProg}
	nkFastpathMu.Unlock()
	return nil
}

func detachNetkitFastpath() {
	nkFastpathMu.Lock()
	defer nkFastpathMu.Unlock()
	for _, l := range nkFastpathLinks {
		_ = l.Close()
	}
	nkFastpathLinks = nil
	for _, p := range nkFastpathProgs {
		_ = p.Close()
	}
	nkFastpathProgs = nil
}
