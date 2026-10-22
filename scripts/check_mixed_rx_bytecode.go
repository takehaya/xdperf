//go:build ignore

// Run from the repository root:
// go run scripts/check_mixed_rx_bytecode.go old.o new.o
// Compare matching toolchain builds; branch displacements may change. No
// register, stack-offset or instruction differences are ignored on normal paths.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/xdperf/pkg/coreelf"
)

type graph struct {
	ins     asm.Instructions
	offsets []int
	index   map[int]int
	funcs   map[string]int
	source  []string
}

func newGraph(p *ebpf.ProgramSpec) *graph {
	g := &graph{ins: p.Instructions, index: map[int]int{}, funcs: map[string]int{}}
	off, source := 0, ""
	for i, x := range g.ins {
		g.offsets = append(g.offsets, off)
		g.index[off] = i
		off += int(x.Size() / asm.InstructionSize)
		if x.Symbol() != "" {
			g.funcs[x.Symbol()] = i
		}
		if x.Source() != nil {
			source = strings.TrimSpace(x.Source().String())
		}
		g.source = append(g.source, source)
	}
	return g
}
func (g *graph) target(i int) int {
	n, ok := g.index[g.offsets[i]+1+int(g.ins[i].Offset)]
	if !ok {
		panic("invalid jump")
	}
	return n
}
func (g *graph) cold(dispatch bool) int {
	for i, x := range g.ins {
		if x.OpCode.Class().IsJump() && x.OpCode.JumpOp() != asm.Call && x.OpCode.JumpOp() != asm.Exit {
			if (!dispatch && g.source[i] == "if (!parsed)") || (dispatch && strings.Contains(g.source[i], "(eth + 1) > end")) {
				return g.target(i)
			}
		}
	}
	panic("cold edge missing")
}
func same(a, b asm.Instruction) bool {
	return a.OpCode == b.OpCode && a.Dst == b.Dst && a.Src == b.Src && a.Offset == b.Offset && a.Constant == b.Constant && a.Reference() == b.Reference()
}
func compareNormal(a, b *ebpf.ProgramSpec, dispatch bool) {
	ga, gb := newGraph(a), newGraph(b)
	ca, cb := ga.cold(dispatch), gb.cold(dispatch)
	queue := [][2]int{{0, 0}}
	seen := map[[2]int]bool{}
	funcs := map[string]bool{}
	total := 0
	for len(queue) > 0 {
		pair := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[pair] {
			continue
		}
		seen[pair] = true
		i, j := pair[0], pair[1]
		x, y := ga.ins[i], gb.ins[j]
		jump := x.OpCode.Class().IsJump() && x.OpCode.JumpOp() != asm.Call && x.OpCode.JumpOp() != asm.Exit
		if jump {
			xx, yy := x, y
			xx.Offset = 0
			yy.Offset = 0
			if !same(xx, yy) {
				panic(fmt.Sprintf("%s normal instruction differs: %d:%v -> %d:%v", a.Name, i, x, j, y))
			}
			ta, tb := ga.target(i), gb.target(j)
			invalid := ga.source[i] == "if (hl < 20 || ip_end < l4 + hl || ip_end > inner.limit)" || (strings.Contains(ga.source[i], "tcp_parse_timestamp(ctx") && x.OpCode.JumpOp() == asm.JSGT)
			if ta == ca {
				if tb != cb {
					panic("cold target mismatch")
				}
			} else if !invalid {
				queue = append(queue, [2]int{ta, tb})
			}
			if x.OpCode.JumpOp() != asm.Ja {
				queue = append(queue, [2]int{i + 1, j + 1})
			}
		} else {
			if !same(x, y) {
				panic(fmt.Sprintf("%s normal instruction differs: %d:%v -> %d:%v", a.Name, i, x, j, y))
			}
			if x.IsFunctionCall() {
				funcs[x.Reference()] = true
			}
			if x.OpCode.JumpOp() != asm.Exit || !x.OpCode.Class().IsJump() {
				queue = append(queue, [2]int{i + 1, j + 1})
			}
		}
		total++
	}
	checked := map[string]bool{}
	for len(funcs) > 0 {
		var name string
		for n := range funcs {
			name = n
			break
		}
		delete(funcs, name)
		if checked[name] {
			continue
		}
		checked[name] = true
		ia, oka := ga.funcs[name]
		ib, okb := gb.funcs[name]
		if !oka || !okb {
			panic("missing function " + name)
		}
		for n := 0; ; n++ {
			enda := ia+n == len(ga.ins) || (n > 0 && ga.ins[ia+n].Symbol() != "")
			endb := ib+n == len(gb.ins) || (n > 0 && gb.ins[ib+n].Symbol() != "")
			if enda || endb {
				if enda != endb {
					panic("function length differs: " + name)
				}
				break
			}
			x, y := ga.ins[ia+n], gb.ins[ib+n]
			if !same(x, y) {
				panic(fmt.Sprintf("%s differs at %d: %v -> %v", name, n, x, y))
			}
			if x.IsFunctionCall() {
				funcs[x.Reference()] = true
			}
			total++
		}
	}
	fmt.Printf("%s: normal graph identical (%d instructions, %d called functions)\n", a.Name, total, len(checked))
}
func main() {
	if len(os.Args) != 3 {
		panic("usage: old.o new.o")
	}
	a, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	b, err := ebpf.LoadCollectionSpec(os.Args[2])
	if err != nil {
		panic(err)
	}
	if err := coreelf.PrepareMixedRXDiagnostics(b); err != nil {
		panic(err)
	}
	for _, name := range []string{"xdp_pass_dummy", "xdp_tx", "xdp_rx", "xdp_tx_checksum", "xdp_tx_csum_diff", "xdp_tx_csum_recalc", "xdp_rx_tcp_server", "xdp_tx_mixed", "xdp_tx_tcp_mixed"} {
		var x, y bytes.Buffer
		if err := a.Programs[name].Instructions.Marshal(&x, binary.LittleEndian); err != nil {
			panic(err)
		}
		if err := b.Programs[name].Instructions.Marshal(&y, binary.LittleEndian); err != nil {
			panic(err)
		}
		if !bytes.Equal(x.Bytes(), y.Bytes()) {
			panic("changed program: " + name)
		}
		fmt.Printf("%s: identical (%d slots)\n", name, x.Len()/8)
	}
	compareNormal(a.Programs["xdp_rx_tcp_mixed"], b.Programs["xdp_rx_tcp_mixed"], false)
	compareNormal(a.Programs["xdp_rx_mixed"], b.Programs["xdp_rx_mixed"], true)
	if a.Programs["xdp_rx_tcp_mixed_ext"] != nil {
		compareNormal(a.Programs["xdp_rx_tcp_mixed_ext"], b.Programs["xdp_rx_tcp_mixed_ext"], false)
	}
	if a.Programs["xdp_tx_tcp_mixed_ext"] != nil {
		var x, y bytes.Buffer
		if err := a.Programs["xdp_tx_tcp_mixed_ext"].Instructions.Marshal(&x, binary.LittleEndian); err != nil {
			panic(err)
		}
		if err := b.Programs["xdp_tx_tcp_mixed_ext"].Instructions.Marshal(&y, binary.LittleEndian); err != nil {
			panic(err)
		}
		if !bytes.Equal(x.Bytes(), y.Bytes()) {
			panic("changed extended mixed TX")
		}
		fmt.Println("xdp_tx_tcp_mixed_ext: identical")
	}
}
