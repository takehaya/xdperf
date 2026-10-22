package xdperf

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
)

// Each exact specialization is verified once per package process. Keep the
// programs bound to their maps, and serialize borrowers until their cleanup.
// Tests which need different constants or map sizes must use private objects.
var mixedTestObjects = struct {
	sync.Mutex
	byFeatures map[coreelf.MixedProgramFeatures]*coreelf.BpfObjects
}{byFeatures: make(map[coreelf.MixedProgramFeatures]*coreelf.BpfObjects)}

func TestMain(m *testing.M) {
	code := m.Run()
	for _, objs := range mixedTestObjects.byFeatures {
		if err := objs.Close(); err != nil {
			code = 1
		}
	}
	os.Exit(code)
}

func loadMixedTestObjects(t *testing.T, features coreelf.MixedProgramFeatures) *coreelf.BpfObjects {
	t.Helper()
	mixedTestObjects.Lock()
	t.Cleanup(mixedTestObjects.Unlock)
	objs := mixedTestObjects.byFeatures[features]
	if objs == nil {
		var err error
		var spec *ebpf.CollectionSpec
		objs, spec, err = coreelf.ReadBaseCollectionWithSizes(map[string]any{"swap_resp": uint32(0)}, map[string]uint32{"diff_map": 100})
		if err == nil {
			err = coreelf.LoadMixedProgramsWithFeatures(objs, spec, features)
		}
		if err != nil {
			if objs != nil {
				objs.Close()
			}
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				t.Fatalf("load mixed test programs: %+v", ve)
			}
			t.Fatal(err)
		}
		mixedTestObjects.byFeatures[features] = objs
	}
	resetMixedTestMaps(t, objs)
	return objs
}

func resetMixedTestMaps(t *testing.T, objs *coreelf.BpfObjects) {
	t.Helper()
	// Reset every data map, including unused entries and every possible CPU.
	// Preserve program arrays: their initialized tail calls are part of the load.
	maps := reflect.ValueOf(objs.BpfMaps)
	for i := 0; i < maps.NumField(); i++ {
		m := maps.Field(i).Interface().(*ebpf.Map)
		switch m.Type() {
		case ebpf.ProgramArray:
			continue
		case ebpf.Array, ebpf.PerCPUArray:
			var zero any = make([]byte, m.ValueSize())
			if m.Type() == ebpf.PerCPUArray {
				values := make([][]byte, ebpf.MustPossibleCPU())
				for cpu := range values {
					values[cpu] = make([]byte, m.ValueSize())
				}
				zero = values
			}
			for key := uint32(0); key < m.MaxEntries(); key++ {
				if err := m.Put(key, zero); err != nil {
					t.Fatalf("reset %s[%d]: %v", m, key, err)
				}
			}
		case ebpf.LRUHash:
			for {
				next, err := m.NextKeyBytes(nil)
				if errors.Is(err, ebpf.ErrKeyNotExist) || (err == nil && next == nil) {
					break
				}
				if err != nil {
					t.Fatalf("iterate %s: %v", m, err)
				}
				if err := m.Delete(next); err != nil {
					t.Fatalf("clear %s: %v", m, err)
				}
			}
		default:
			t.Fatalf("unhandled shared map type: %s", m)
		}
	}
}

// Exercise reuse with dirty entries outside the next test's active flow range,
// plus per-CPU state/counters. A fresh borrower must see the initial zero state.
func TestMixedBPFIsolation(t *testing.T) {
	features := coreelf.MixedProgramFeatures{}
	var first *coreelf.BpfObjects
	t.Run("dirty", func(t *testing.T) {
		first = loadMixedTestObjects(t, features)
		if err := first.TcpFlowMap.Put(first.TcpFlowMap.MaxEntries()-1, coreelf.BpfTcpFlow{State: tcpFlowDone}); err != nil {
			t.Fatal(err)
		}
		if err := first.TcpTemplateMap.Put(first.TcpTemplateMap.MaxEntries()-1, coreelf.BpfTcpTemplate{Cfg: coreelf.BpfTcpCfg{Drain: 1}}); err != nil {
			t.Fatal(err)
		}
		states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
		for i := range states {
			states[i].SelectedGroup = 7
		}
		if err := first.MixedStateMap.Put(uint32(0), states); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("clean", func(t *testing.T) {
		objs := loadMixedTestObjects(t, features)
		if first != nil && objs != first {
			t.Fatal("specialization was loaded again")
		}
		var flow coreelf.BpfTcpFlow
		if err := objs.TcpFlowMap.Lookup(objs.TcpFlowMap.MaxEntries()-1, &flow); err != nil || flow.State != 0 {
			t.Fatalf("stale flow: %+v, %v", flow, err)
		}
		var tmpl coreelf.BpfTcpTemplate
		if err := objs.TcpTemplateMap.Lookup(objs.TcpTemplateMap.MaxEntries()-1, &tmpl); err != nil || tmpl.Cfg.Drain != 0 {
			t.Fatalf("stale template: %+v, %v", tmpl.Cfg, err)
		}
		states := make([]coreelf.BpfMixedState, ebpf.MustPossibleCPU())
		if err := objs.MixedStateMap.Lookup(uint32(0), states); err != nil {
			t.Fatal(err)
		}
		for i, state := range states {
			if state != (coreelf.BpfMixedState{}) {
				t.Fatalf("stale CPU %d: %+v", i, state)
			}
		}
	})
}
