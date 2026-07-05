package scx

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// schedulerName must match .name in src/scx_prog.c's xdperf_ops.
const schedulerName = "xdperf"

// maxCPUs must match MAX_CPUS in src/scx_prog.c.
const maxCPUs = 1024

// Options configures Attach.
type Options struct {
	// WorkerTIDByCPU maps each worker CPU to the kernel thread ID of the
	// worker pinned there. Every worker must be registered before attach:
	// the scheduler identifies workers by (TGID, TID).
	WorkerTIDByCPU map[int]int
	// TGID of the xdperf process; guards worker matching against TID reuse.
	TGID   int
	Logger *zap.Logger
}

// ExitRecord mirrors struct scx_exit_record in src/scx_prog.c.
type ExitRecord struct {
	Set      uint32
	Kind     int32
	ExitCode int64
	Reason   [64]byte
	Msg      [128]byte
}

// Manager owns a loaded-and-attached xdperf scheduler. Closing it detaches
// the scheduler and the kernel falls back to its default scheduler; the same
// happens automatically if the process dies, because the attachment is a BPF
// link tied to this process's file descriptors.
type Manager struct {
	logger    *zap.Logger
	objs      ScxObjects
	link      link.Link
	closeOnce sync.Once
	closeErr  error
}

// Attach loads the sched_ext scheduler, registers the worker threads, and
// enables it system-wide (full switch: all normal-class tasks run under it
// until Close). Callers must have every worker thread pinned and parked
// before calling; no TX should happen before Attach returns.
func Attach(opts Options) (*Manager, error) {
	if err := Supported(); err != nil {
		return nil, err
	}
	if len(opts.WorkerTIDByCPU) == 0 {
		return nil, fmt.Errorf("no worker TIDs to register")
	}
	if info := Detect(); info.State != "disabled" {
		return nil, fmt.Errorf("another sched_ext scheduler is active (%q, state=%q); only one BPF scheduler can run at a time", info.RootOps, info.State)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	var mask [maxCPUs / 64]uint64
	for cpu := range opts.WorkerTIDByCPU {
		if cpu < 0 || cpu >= maxCPUs {
			return nil, fmt.Errorf("worker CPU %d out of range (max %d)", cpu, maxCPUs-1)
		}
		mask[cpu/64] |= 1 << (cpu % 64)
	}

	spec, err := LoadScx()
	if err != nil {
		return nil, fmt.Errorf("failed to load scx collection spec: %w", err)
	}
	if err := spec.Variables["xdperf_tgid"].Set(uint32(opts.TGID)); err != nil {
		return nil, fmt.Errorf("failed to set xdperf_tgid: %w", err)
	}
	if err := spec.Variables["worker_cpu_mask"].Set(mask); err != nil {
		return nil, fmt.Errorf("failed to set worker_cpu_mask: %w", err)
	}

	var objs ScxObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, fmt.Errorf("scx scheduler rejected by verifier: %+v", verr)
		}
		return nil, fmt.Errorf("failed to load scx scheduler: %w", err)
	}

	for cpu, tid := range opts.WorkerTIDByCPU {
		if err := objs.WorkerTids.Put(uint32(tid), uint32(cpu)); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("failed to register worker tid %d: %w", tid, err)
		}
	}

	l, err := link.AttachStructOps(link.StructOpsOptions{Map: objs.XdperfOps})
	if err != nil {
		_ = objs.Close()
		if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("failed to enable scx scheduler (another scheduler grabbed sched_ext first?): %w", err)
		}
		return nil, fmt.Errorf("failed to attach scx scheduler: %w", err)
	}

	m := &Manager{logger: opts.Logger, objs: objs, link: l}

	// The link either enabled the scheduler or the whole run is invalid;
	// verify through sysfs rather than trusting the syscall alone.
	if info := Detect(); info.State != "enabled" || info.RootOps != schedulerName {
		err := fmt.Errorf("scx attach did not take effect (state=%q ops=%q)", info.State, info.RootOps)
		_ = m.Close()
		return nil, err
	}

	if m.logger != nil {
		m.logger.Info("sched_ext scheduler attached (full switch)",
			zap.String("ops", schedulerName),
			zap.Int("workers", len(opts.WorkerTIDByCPU)),
		)
	}
	return m, nil
}

// CheckHealth returns an error when the scheduler is no longer the active
// one — most importantly after a stall-watchdog eject, which silently falls
// back to the default scheduler and would invalidate any measurement.
func (m *Manager) CheckHealth() error {
	if rec, ok := m.exitRecord(); ok {
		return fmt.Errorf("scx scheduler exited mid-run: kind=%d exit_code=%d reason=%q msg=%q",
			rec.Kind, rec.ExitCode, cstr(rec.Reason[:]), cstr(rec.Msg[:]))
	}
	if info := Detect(); info.State != "enabled" || info.RootOps != schedulerName {
		return fmt.Errorf("scx scheduler no longer active (state=%q ops=%q)", info.State, info.RootOps)
	}
	return nil
}

func (m *Manager) exitRecord() (ExitRecord, bool) {
	var rec ExitRecord
	if m.objs.ExitInfo == nil {
		return rec, false
	}
	var key uint32
	if err := m.objs.ExitInfo.Lookup(&key, &rec); err != nil {
		return rec, false
	}
	return rec, rec.Set != 0
}

// Close detaches the scheduler (the kernel reverts to its default scheduler)
// and releases the BPF objects. Idempotent.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		if m.link != nil {
			m.closeErr = m.link.Close()
		}
		if rec, ok := m.exitRecord(); ok && m.logger != nil {
			m.logger.Debug("scx scheduler exit record",
				zap.Int32("kind", rec.Kind),
				zap.Int64("exit_code", rec.ExitCode),
				zap.String("reason", cstr(rec.Reason[:])),
			)
		}
		_ = m.objs.Close()
	})
	return m.closeErr
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
