package scx

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// requireSchedExt skips on kernels that cannot run the xdperf scheduler:
// no CONFIG_SCHED_EXT (sysfs absent) or pre-6.13 kfunc names. This keeps the
// vimto matrix legs 6.1/6.6/6.12 and the 6.8 dev boxes green.
func requireSchedExt(t *testing.T) {
	t.Helper()
	if err := Supported(); err != nil {
		t.Skipf("skipping: %v", err)
	}
}

func TestScxLoad(t *testing.T) {
	requireSchedExt(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("failed to remove memlock limit: %v", err)
	}

	spec, err := LoadScx()
	if err != nil {
		t.Fatalf("failed to load collection spec: %v", err)
	}
	if err := spec.Variables["xdperf_tgid"].Set(uint32(os.Getpid())); err != nil {
		t.Fatalf("failed to set xdperf_tgid: %v", err)
	}
	var mask [maxCPUs / 64]uint64
	mask[0] = 1 // pretend CPU 0 is a worker CPU
	if err := spec.Variables["worker_cpu_mask"].Set(mask); err != nil {
		t.Fatalf("failed to set worker_cpu_mask: %v", err)
	}

	var objs ScxObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		// %+v prints the full verifier log (same convention as coreelf).
		t.Fatalf("failed to load scx scheduler: %+v", err)
	}
	defer objs.Close()

	if objs.XdperfOps.Type() != ebpf.StructOpsMap {
		t.Errorf("xdperf_ops map type = %v, want StructOpsMap", objs.XdperfOps.Type())
	}
}

func TestScxAttachDetach(t *testing.T) {
	requireSchedExt(t)
	if info := Detect(); info.State != "disabled" {
		t.Skipf("skipping: another sched_ext scheduler is active (%q)", info.RootOps)
	}
	if runtime.NumCPU() < 2 {
		t.Skip("skipping: needs >= 2 CPUs (one worker + one housekeeping)")
	}

	// Register this test thread as the worker on the last CPU, exactly like
	// runTXPacket registers pinned TX workers.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	workerCPU := runtime.NumCPU() - 1

	mgr, err := Attach(Options{
		WorkerTIDByCPU: map[int]int{workerCPU: unix.Gettid()},
		TGID:           os.Getpid(),
	})
	if err != nil {
		t.Fatalf("Attach failed: %+v", err)
	}

	if info := Detect(); info.State != "enabled" || info.RootOps != schedulerName {
		t.Errorf("after attach: state=%q ops=%q, want enabled/%s", info.State, info.RootOps, schedulerName)
	}
	if err := mgr.CheckHealth(); err != nil {
		t.Errorf("CheckHealth right after attach: %v", err)
	}

	// Run a moment under the policy so scheduling paths actually execute.
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if err := mgr.CheckHealth(); err != nil {
		t.Errorf("CheckHealth while running: %v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Detach is asynchronous on the kernel side; poll for the fallback.
	var last Info
	for i := 0; i < 50; i++ {
		last = Detect()
		if last.State == "disabled" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if last.State != "disabled" {
		t.Errorf("after close: state=%q, want disabled", last.State)
	}
	if err := mgr.Close(); err != nil {
		t.Errorf("second Close must be idempotent, got %v", err)
	}
}

func TestScxAttachValidation(t *testing.T) {
	requireSchedExt(t)
	if _, err := Attach(Options{TGID: os.Getpid()}); err == nil {
		t.Error("Attach without worker TIDs must fail")
	}
	if _, err := Attach(Options{
		WorkerTIDByCPU: map[int]int{maxCPUs: 1},
		TGID:           os.Getpid(),
	}); err == nil {
		t.Error("Attach with out-of-range CPU must fail")
	}
}
