package coreelf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// PrepareMixedRXDiagnostics redirects only the existing invalid-header edges.
// Adding a C call there changes LLVM's allocation throughout the normal RX path.
// Call this before manually loading mixed programs obtained from LoadBpf; the
// collection readers and LoadMixedProgramsWithFeatures already do so.
func PrepareMixedRXDiagnostics(spec *ebpf.CollectionSpec) error {
	p := spec.Programs["xdp_rx_tcp_mixed"]
	if p == nil {
		return fmt.Errorf("mixed RX program missing")
	}
	const label = "mixed_rx_invalid_count"
	for _, ins := range p.Instructions {
		if ins.Symbol() == label {
			return prepareMixedRXDispatcher(spec)
		}
	}
	// BTF source lines survive bpf2go's debug stripping. Fail closed if compiler
	// changes invalidate this shape, rather than silently leaving drops uncounted.
	const condition = "if (hl < 20 || ip_end < l4 + hl || ip_end > inner.limit)"
	var edges []int
	source := ""
	mainEnd, mainSlots := 0, 0
	offset := 0
	target := -1
	countFound := false
	offsets := make([]int, len(p.Instructions))
	for i, ins := range p.Instructions {
		offsets[i] = offset
		if ins.Symbol() == "mixed_rx_count" {
			countFound = true
		}
		if i > 0 && mainEnd == 0 && ins.Symbol() != "" {
			mainEnd = i
			mainSlots = offset
		}
		if ins.Source() != nil {
			source = strings.TrimSpace(ins.Source().String())
		}
		if mainEnd == 0 && source == condition && ins.OpCode.Class().IsJump() {
			if ins.OpCode != asm.JGT.Op(asm.RegSource) {
				return fmt.Errorf("unexpected mixed RX length branch: %s", ins.OpCode)
			}
			dest := offset + 1 + int(ins.Offset)
			if target != -1 && target != dest {
				return fmt.Errorf("mixed RX length branches have different targets")
			}
			target = dest
			edges = append(edges, i)
		}
		offset += int(ins.Size() / asm.InstructionSize)
	}
	if len(edges) != 3 || mainEnd == 0 || !countFound {
		return fmt.Errorf("mixed RX diagnostic shape changed: branches=%d main=%d counter=%v", len(edges), mainEnd, countFound)
	}
	// The old shared return must copy the preselected verdict to r0 and exit.
	returnIndex := -1
	for i, off := range offsets[:mainEnd] {
		if off == target {
			returnIndex = i
			break
		}
	}
	if returnIndex < 0 || returnIndex+1 >= mainEnd || p.Instructions[returnIndex].OpCode != asm.Mov.Op(asm.RegSource) || p.Instructions[returnIndex].Dst != asm.R0 || p.Instructions[returnIndex+1].OpCode != asm.Exit.Op(asm.ImmSource) {
		return fmt.Errorf("mixed RX invalid-header return changed")
	}
	// All subprogram calls must retain symbolic references so cilium/ebpf can
	// relocate them after insertion. Numeric branches stay inside each function.
	for _, ins := range p.Instructions {
		if ins.IsFunctionCall() && ins.Reference() == "" {
			return fmt.Errorf("mixed RX has an unrelocatable subprogram call")
		}
	}
	block := asm.Instructions{
		asm.Mov.Imm(asm.R1, 5).WithSymbol(label), // MIXED_RX_INVALID_TCP
		asm.Call.Label("mixed_rx_count"),
		asm.Mov.Imm(asm.R0, 1), // XDP_DROP
		asm.Return(),
	}
	updated := make(asm.Instructions, 0, len(p.Instructions)+len(block))
	updated = append(updated, p.Instructions[:mainEnd]...)
	updated = append(updated, block...)
	updated = append(updated, p.Instructions[mainEnd:]...)
	for _, i := range edges {
		distance := mainSlots - offsets[i] - 1
		if distance < 0 || distance > 32767 {
			return fmt.Errorf("mixed RX diagnostic branch out of range")
		}
		updated[i].Offset = int16(distance)
	}
	p.Instructions = updated
	return prepareMixedRXDispatcher(spec)
}

// Dispatcher PASS edges share an exit with the tail-call failure (ABORTED)
// fallthrough. Redirect only the explicit PASS jumps, preserving that fallthrough.
func prepareMixedRXDispatcher(spec *ebpf.CollectionSpec) error {
	p, account := spec.Programs["xdp_rx_mixed"], spec.Programs["xdp_mixed_rx_account"]
	if p == nil || account == nil || len(p.Instructions) == 0 {
		return fmt.Errorf("mixed RX dispatcher accounting programs missing")
	}
	const label = "mixed_rx_outer_pass"
	for _, ins := range p.Instructions {
		if ins.Symbol() == label {
			return nil
		}
	}
	if p.Instructions[0].OpCode != asm.Mov.Op(asm.ImmSource) || p.Instructions[0].Dst != asm.R0 || p.Instructions[0].Constant != 2 {
		return fmt.Errorf("mixed RX dispatcher PASS verdict changed")
	}
	offset, target, slots := 0, -1, 0
	offsets := make([]int, len(p.Instructions))
	for i, ins := range p.Instructions {
		offsets[i] = offset
		if target < 0 && ins.OpCode == asm.JGT.Op(asm.RegSource) {
			target = offset + 1 + int(ins.Offset)
		}
		offset += int(ins.Size() / asm.InstructionSize)
	}
	slots = offset
	if target < 0 {
		return fmt.Errorf("mixed RX dispatcher PASS edge missing")
	}
	exitFound := false
	for i, off := range offsets {
		if off == target {
			exitFound = p.Instructions[i].OpCode == asm.Exit.Op(asm.ImmSource)
		}
	}
	if !exitFound {
		return fmt.Errorf("mixed RX dispatcher shared exit changed")
	}
	firstSub := 0
	for i, ins := range account.Instructions {
		if i > 0 && ins.Symbol() != "" {
			firstSub = i
			break
		}
	}
	if firstSub == 0 {
		return fmt.Errorf("mixed RX dispatcher accounting subprograms missing")
	}
	updated := append(asm.Instructions(nil), p.Instructions...)
	edges := 0
	for i, ins := range updated {
		if ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit && offsets[i]+1+int(ins.Offset) == target {
			distance := slots - offsets[i] - 1
			if distance < 0 || distance > 32767 {
				return fmt.Errorf("mixed RX dispatcher branch out of range")
			}
			updated[i].Offset = int16(distance)
			edges++
		}
	}
	if edges < 1 {
		return fmt.Errorf("mixed RX dispatcher PASS jumps missing")
	}
	updated = append(updated, asm.Call.Label("mixed_rx_outer").WithSymbol(label), asm.Mov.Imm(asm.R0, 2), asm.Return())
	updated = append(updated, account.Instructions[firstSub:]...)
	p.Instructions = updated
	return nil
}
