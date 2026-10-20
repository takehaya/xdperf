package xdperf

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cilium/ebpf"
)

type packetBatchPlan struct {
	packets   uint64
	repeat    uint32
	interval  time.Duration
	batchSize uint32
	infinite  bool
}

// calculatePacketBatchPlan distributes the remainder by worker slot, not CPU ID.
// Packet budgets stay uint64; only individual BPF Run calls use uint32 repeats.
func calculatePacketBatchPlan(cfg Config, slot int) packetBatchPlan {
	workers := uint64(cfg.Parallelism)
	packets := cfg.Count / workers
	if uint64(slot) < cfg.Count%workers {
		packets++
	}
	plan := packetBatchPlan{
		packets:   packets,
		repeat:    uint32(max(1, min(packets, math.MaxUint32))),
		batchSize: cfg.BatchSize,
		infinite:  cfg.Infinite,
	}
	if cfg.Infinite {
		plan.repeat = 1 << 20
		return plan
	}
	if cfg.PPS == 0 {
		return plan
	}

	// Keep the 100ms target interval. Divide before narrowing to uint32,
	// and retain fractional per-worker PPS when PPS < Parallelism.
	repeat := max(uint64(1), cfg.PPS/workers/10)
	plan.repeat = uint32(max(1, min(repeat, packets, math.MaxUint32)))
	ppsPerCPU := float64(cfg.PPS) / float64(workers)
	plan.interval = max(time.Millisecond, time.Duration(float64(plan.repeat)*float64(time.Second)/ppsPerCPU))
	plan.batchSize = 1
	return plan
}

func (p packetBatchPlan) totalBatches() uint64 {
	if p.infinite {
		return 0
	}
	batches := p.packets / uint64(p.repeat)
	if p.packets%uint64(p.repeat) != 0 {
		batches++
	}
	return batches
}

// runPacketBatches owns its RunOptions copy: workers must not share Repeat,
// since the final batch can differ between workers. run is injectable so the
// actual send loop can be tested without loading BPF programs.
func runPacketBatches(ctx context.Context, run func(*ebpf.RunOptions) (uint32, error), opts ebpf.RunOptions, plan packetBatchPlan) error {
	opts.BatchSize = plan.batchSize
	var ticks <-chan time.Time
	if plan.interval > 0 {
		ticker := time.NewTicker(plan.interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	remaining := plan.packets
	for plan.infinite || remaining > 0 {
		if ctx.Err() != nil {
			return nil
		}
		opts.Repeat = plan.repeat
		if !plan.infinite {
			opts.Repeat = uint32(min(uint64(plan.repeat), remaining))
		}
		ret, err := run(&opts)
		if err != nil {
			return fmt.Errorf("bpf_prog_run failed: %w", err)
		}
		if ret != 0 {
			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
		}
		if !plan.infinite {
			remaining -= uint64(opts.Repeat)
			if remaining == 0 {
				return nil
			}
		}
		if ticks != nil {
			select {
			case <-ticks:
			case <-ctx.Done():
				return nil
			}
		}
	}
	return nil
}
