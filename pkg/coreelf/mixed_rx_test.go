package coreelf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestMixedRXInstrumentation(t *testing.T) {
	spec, err := LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	before := spec.Copy()
	if err := PrepareMixedRXDiagnostics(spec); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"xdp_rx_tcp_mixed", "xdp_rx_tcp_mixed_ext"} {
		p := spec.Programs[name]
		old := before.Programs[name].Instructions
		added, branches := 0, 0
		for i, j := 0, 0; i < len(p.Instructions) && j < len(old); i++ {
			if p.Instructions[i].Symbol() == "mixed_rx_unmatched_count" {
				added++
				i += 2
				continue
			}
			if p.Instructions[i].Symbol() == "mixed_rx_invalid_count" {
				added++
				i += 3
				continue
			}
			a, b := old[j], p.Instructions[i]
			j++
			if a.Offset != b.Offset {
				if !a.OpCode.Class().IsJump() {
					t.Fatalf("unexpected changed instruction: %v", a)
				}
				branches++
				b.Offset = a.Offset
			}
			if a.OpCode != b.OpCode || a.Dst != b.Dst || a.Src != b.Src || a.Constant != b.Constant || a.Offset != b.Offset || a.Reference() != b.Reference() {
				t.Fatalf("changed original instruction: %v -> %v", a, b)
			}
		}
		wantBranches := 3
		if name == "xdp_rx_tcp_mixed_ext" {
			wantBranches = 4
		}
		if (name == "xdp_rx_tcp_mixed" && (added != 1 || branches != wantBranches)) || (name == "xdp_rx_tcp_mixed_ext" && (added != 2 || branches <= wantBranches)) {
			t.Fatalf("blocks=%d branches=%d", added, branches)
		}
		encoded := func(s *ebpf.ProgramSpec) []byte {
			var b bytes.Buffer
			if err := s.Instructions.Marshal(&b, binary.LittleEndian); err != nil {
				t.Fatal(err)
			}
			return b.Bytes()
		}
		once := encoded(p)
		if err := PrepareMixedRXDiagnostics(spec); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(once, encoded(p)) {
			t.Fatal("instrumentation was not idempotent")
		}
	}
	for name, orig := range before.Programs {
		if name != "xdp_rx_tcp_mixed" && name != "xdp_rx_tcp_mixed_ext" && name != "xdp_rx_mixed" && !instructionsEqual(t, orig, spec.Programs[name]) {
			t.Fatalf("modified %s", name)
		}
	}
}

func TestMixedRXInstrumentationFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing_program", "missing_source", "wrong_branch", "different_target", "wrong_return", "numeric_call", "dispatcher_missing", "dispatcher_empty", "dispatcher_verdict", "dispatcher_edge", "dispatcher_exit", "account_missing", "account_empty"} {
		t.Run(kind, func(t *testing.T) {
			spec, err := LoadBpf()
			if err != nil {
				t.Fatal(err)
			}
			p := spec.Programs["xdp_rx_tcp_mixed"]
			switch kind {
			case "dispatcher_missing":
				delete(spec.Programs, "xdp_rx_mixed")
			case "dispatcher_empty":
				spec.Programs["xdp_rx_mixed"].Instructions = nil
			case "dispatcher_verdict":
				spec.Programs["xdp_rx_mixed"].Instructions[0].Constant = 1
			case "dispatcher_edge":
				for i, ins := range spec.Programs["xdp_rx_mixed"].Instructions {
					if ins.OpCode == asm.JGT.Op(asm.RegSource) {
						spec.Programs["xdp_rx_mixed"].Instructions[i].Offset++
						break
					}
				}
			case "dispatcher_exit":
				for i, ins := range spec.Programs["xdp_rx_mixed"].Instructions {
					if ins.OpCode == asm.Exit.Op(asm.ImmSource) {
						spec.Programs["xdp_rx_mixed"].Instructions[i] = asm.Mov.Imm(asm.R0, 1)
						break
					}
				}
			case "account_missing":
				delete(spec.Programs, "xdp_mixed_rx_account")
			case "account_empty":
				spec.Programs["xdp_mixed_rx_account"].Instructions = nil
			case "missing_program":
				delete(spec.Programs, "xdp_rx_tcp_mixed")
			case "missing_source":
				for i := range p.Instructions {
					p.Instructions[i].Metadata = asm.Metadata{}
				}
			case "numeric_call":
				for i, ins := range p.Instructions {
					if ins.IsFunctionCall() {
						p.Instructions[i] = ins.WithReference("")
						break
					}
				}
			default:
				offset := 0
				for i, ins := range p.Instructions {
					if ins.Source() != nil && ins.Source().String() == "    if (hl < 20 || ip_end < l4 + hl || ip_end > inner.limit)" {
						switch kind {
						case "wrong_branch":
							p.Instructions[i].OpCode = asm.JEq.Op(asm.RegSource)
						case "different_target":
							p.Instructions[i].Offset++
						case "wrong_return":
							target := offset + 1 + int(ins.Offset)
							off := 0
							for j, x := range p.Instructions {
								if off == target {
									p.Instructions[j] = asm.Mov.Imm(asm.R0, 2)
									break
								}
								off += int(x.Size() / asm.InstructionSize)
							}
						}
						break
					}
					offset += int(ins.Size() / asm.InstructionSize)
				}
			}
			if err := PrepareMixedRXDiagnostics(spec); err == nil {
				t.Fatal("accepted unsupported instruction layout")
			}
		})
	}
}

func instructionsEqual(t *testing.T, a, b *ebpf.ProgramSpec) bool {
	t.Helper()
	var x, y bytes.Buffer
	if err := a.Instructions.Marshal(&x, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	if err := b.Instructions.Marshal(&y, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(x.Bytes(), y.Bytes())
}

func TestMixedRXExtendedFailsClosed(t *testing.T) {
	for _, kind := range []string{"timestamp_branch", "unmatched_branch", "context_argument", "tail_call", "neighbor_check", "diagnostic_source"} {
		t.Run(kind, func(t *testing.T) {
			spec, err := LoadBpf()
			if err != nil {
				t.Fatal(err)
			}
			p := spec.Programs["xdp_rx_tcp_mixed_ext"]
			switch kind {
			case "timestamp_branch":
				for i, ins := range p.Instructions {
					if ins.OpCode == asm.JSLT.Imm32(asm.R0, 0, "").OpCode && ins.Dst == asm.R0 {
						p.Instructions[i].OpCode = asm.JSGE.Op(asm.RegSource)
						break
					}
				}
			case "unmatched_branch":
				for i, ins := range p.Instructions {
					if ins.Source() != nil && strings.TrimSpace(ins.Source().String()) == "if (!parsed)" {
						p.Instructions[i].OpCode = asm.JNE.Op(asm.ImmSource)
						break
					}
				}
			case "context_argument", "tail_call":
				for i, ins := range p.Instructions {
					if ins.OpCode == asm.Call.Op(asm.ImmSource) && ins.Constant == int64(asm.FnTailCall) {
						if kind == "tail_call" {
							p.Instructions[i].Constant = int64(asm.FnGetSmpProcessorId)
						} else {
							for j := i - 1; j >= 0; j-- {
								if p.Instructions[j].Dst == asm.R1 {
									p.Instructions[j] = asm.Mov.Imm(asm.R1, 0)
									break
								}
							}
						}
						break
					}
				}
			case "neighbor_check":
				for i, ins := range p.Instructions {
					if ins.Source() != nil && strings.TrimSpace(ins.Source().String()) == "if (inner.neighbor)" {
						p.Instructions[i].Metadata = asm.Metadata{}
					}
				}
			case "diagnostic_source":
				for i, ins := range spec.Programs["xdp_rx_tcp_mixed"].Instructions {
					if ins.Symbol() == "mixed_rx_terminal" {
						spec.Programs["xdp_rx_tcp_mixed"].Instructions[i] = ins.WithSymbol("missing_terminal")
						break
					}
				}
			}
			if err := PrepareMixedRXDiagnostics(spec); err == nil {
				t.Fatal("accepted changed extended RX layout")
			}
		})
	}
}
