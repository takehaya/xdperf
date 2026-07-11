package xdperf

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Scheduling policy names accepted by --sched-policy. Empty keeps the kernel
// default (SCHED_OTHER / EEVDF) untouched.
const (
	SchedPolicyNone = ""
	SchedPolicyFIFO = "fifo"
	SchedPolicyRR   = "rr"
)

const rtRuntimePath = "/proc/sys/kernel/sched_rt_runtime_us"

// applyWorkerSchedPolicy switches the calling thread to the configured
// realtime scheduling class. It must run on a LockOSThread'ed worker thread;
// pid 0 targets exactly that thread, so the stats/OTLP goroutines keep normal
// scheduling.
func (x *Xdperf) applyWorkerSchedPolicy() error {
	var policy uint32
	switch x.cfg.SchedPolicy {
	case SchedPolicyNone:
		return nil
	case SchedPolicyFIFO:
		policy = unix.SCHED_FIFO
	case SchedPolicyRR:
		policy = unix.SCHED_RR
	default:
		return fmt.Errorf("unknown sched policy %q", x.cfg.SchedPolicy)
	}
	attr := &unix.SchedAttr{
		Policy:   policy,
		Priority: uint32(x.cfg.SchedPriority),
	}
	if err := unix.SchedSetAttr(0, attr, 0); err != nil {
		return fmt.Errorf("failed to set %s priority %d (CAP_SYS_NICE/root required): %w",
			x.cfg.SchedPolicy, x.cfg.SchedPriority, err)
	}
	return nil
}

// setupRTThrottling inspects the kernel RT throttling knob when a realtime
// policy is requested. Realtime tasks are throttled to sched_rt_runtime_us per
// second by default, which injects a periodic stall (~50ms/s) into busy
// workers. With --disable-rt-throttling the knob is set to -1 for the run and
// restored through the cleanup list on Close (a SIGKILL skips the restore).
func (x *Xdperf) setupRTThrottling() error {
	if x.cfg.SchedPolicy == SchedPolicyNone {
		return nil
	}
	raw, err := os.ReadFile(rtRuntimePath)
	if err != nil {
		// The knob is absent on some kernel configs; RT scheduling still works.
		x.Logger.Debug("cannot read sched_rt_runtime_us", zap.Error(err))
		return nil
	}
	cur := strings.TrimSpace(string(raw))
	if cur == "-1" {
		return nil
	}
	if !x.cfg.DisableRTThrottling {
		x.Logger.Warn("RT throttling is active; realtime workers will stall periodically",
			zap.String("sched_rt_runtime_us", cur),
			zap.String("hint", "pass --disable-rt-throttling to lift it for this run"),
		)
		return nil
	}
	if err := os.WriteFile(rtRuntimePath, []byte("-1"), 0); err != nil {
		return fmt.Errorf("failed to disable RT throttling: %w", err)
	}
	x.Logger.Info("RT throttling disabled for this run",
		zap.String("previous_sched_rt_runtime_us", cur),
	)
	x.cleanupFnList = append(x.cleanupFnList, func(context.Context) error {
		if err := os.WriteFile(rtRuntimePath, []byte(cur), 0); err != nil {
			return fmt.Errorf("failed to restore sched_rt_runtime_us=%s: %w", cur, err)
		}
		x.Logger.Info("RT throttling restored", zap.String("sched_rt_runtime_us", cur))
		return nil
	})
	return nil
}
