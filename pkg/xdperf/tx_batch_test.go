package xdperf

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestPacketBatchPlan(t *testing.T) {
	tests := []struct {
		name       string
		count, pps uint64
		workers    int
		packets    []uint64
		repeats    []uint32
		batches    uint64
		interval   time.Duration
	}{
		{"reported truncation", 25600, 20000, 1, []uint64{25600}, []uint32{2000}, 13, 100 * time.Millisecond},
		{"exact batches", 16000, 20000, 1, []uint64{16000}, []uint32{2000}, 8, 100 * time.Millisecond},
		{"worker and batch remainders", 25601, 20000, 3, []uint64{8534, 8534, 8533}, []uint32{666, 666, 666}, 13, 99900 * time.Microsecond},
		{"unlimited worker remainder", 101, 0, 3, []uint64{34, 34, 33}, []uint32{34, 34, 33}, 1, 0},
		{"PPS below workers", 7, 2, 4, []uint64{2, 2, 2, 1}, []uint32{1, 1, 1, 1}, 2, 2 * time.Second},
		{"small count", 3, 20000, 1, []uint64{3}, []uint32{3}, 1, 150 * time.Microsecond},
		{"zero count", 0, 20000, 1, []uint64{0}, []uint32{1}, 0, 50 * time.Microsecond},
		{"unlimited uint32 boundary", math.MaxUint32 + 7, 0, 1, []uint64{math.MaxUint32 + 7}, []uint32{math.MaxUint32}, 2, 0},
		{"PPS uint32 boundary", math.MaxUint32 + 7, math.MaxUint64, 1, []uint64{math.MaxUint32 + 7}, []uint32{math.MaxUint32}, 2, time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Count: tt.count, PPS: tt.pps, Parallelism: tt.workers, BatchSize: 64}
			var total uint64
			for slot := range tt.workers {
				plan := calculatePacketBatchPlan(cfg, slot)
				if plan.packets != tt.packets[slot] || plan.repeat != tt.repeats[slot] {
					t.Fatalf("slot %d: packets/repeat = %d/%d, want %d/%d", slot, plan.packets, plan.repeat, tt.packets[slot], tt.repeats[slot])
				}
				if slot == 0 && plan.totalBatches() != tt.batches {
					t.Fatalf("batches = %d, want %d", plan.totalBatches(), tt.batches)
				}
				wantInterval := tt.interval
				if cfg.PPS > 0 {
					wantInterval = max(time.Millisecond, wantInterval)
				}
				if plan.interval != wantInterval {
					t.Fatalf("interval = %v, want %v", plan.interval, wantInterval)
				}
				wantBatchSize := cfg.BatchSize
				if cfg.PPS > 0 {
					wantBatchSize = 1
				}
				if plan.batchSize != wantBatchSize {
					t.Fatalf("batch size = %d, want %d", plan.batchSize, wantBatchSize)
				}

				// Exercise the production send loop without BPF or real pacing.
				// Check every call, including the shortened final batch.
				plan.interval = 0
				var sent, calls uint64
				opts := ebpf.RunOptions{Repeat: 99}
				err := runPacketBatches(context.Background(), func(got *ebpf.RunOptions) (uint32, error) {
					want := uint32(min(uint64(plan.repeat), plan.packets-sent))
					if got.Repeat == 0 || got.Repeat != want || got.BatchSize != wantBatchSize {
						t.Fatalf("run options = %+v, want repeat %d, batch size %d", got, want, wantBatchSize)
					}
					sent += uint64(got.Repeat)
					calls++
					return 0, nil
				}, opts, plan)
				if err != nil || sent != plan.packets || calls != plan.totalBatches() {
					t.Fatalf("sent %d in %d calls, err %v; want %d in %d calls", sent, calls, err, plan.packets, plan.totalBatches())
				}
				if opts.Repeat != 99 {
					t.Fatal("worker modified shared RunOptions")
				}
				total += sent
			}
			if total != cfg.Count {
				t.Fatalf("total sent = %d, want %d", total, cfg.Count)
			}
		})
	}
}

func TestPacketBatchPlanUint64Budget(t *testing.T) {
	plan := calculatePacketBatchPlan(Config{Count: math.MaxUint64, PPS: 10, Parallelism: 1}, 0)
	if plan.packets != math.MaxUint64 || plan.repeat != 1 || plan.totalBatches() != math.MaxUint64 {
		t.Fatalf("budget was truncated: %+v", plan)
	}
}

func TestPacketBatchesInfinite(t *testing.T) {
	plan := calculatePacketBatchPlan(Config{Count: 7, PPS: 20000, Parallelism: 3, BatchSize: 64, Infinite: true}, 0)
	if plan.repeat != 1<<20 || plan.interval != 0 || plan.totalBatches() != 0 || plan.batchSize != 64 {
		t.Fatalf("infinite plan = %+v", plan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := runPacketBatches(ctx, func(opts *ebpf.RunOptions) (uint32, error) {
		if opts.Repeat != 1<<20 || opts.BatchSize != 64 {
			t.Fatalf("infinite options = %+v", opts)
		}
		calls++
		if calls == 3 {
			cancel()
		}
		return 0, nil
	}, ebpf.RunOptions{}, plan)
	if err != nil || calls != 3 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}

func TestPacketBatchesCancellation(t *testing.T) {
	for _, beforeRun := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		if beforeRun {
			cancel()
		}
		calls := 0
		// A long interval proves cancellation interrupts the pacing wait.
		plan := packetBatchPlan{packets: 5, repeat: 2, interval: time.Hour, batchSize: 1}
		err := runPacketBatches(ctx, func(*ebpf.RunOptions) (uint32, error) {
			calls++
			cancel()
			return 0, nil
		}, ebpf.RunOptions{}, plan)
		cancel()
		wantCalls := 1
		if beforeRun {
			wantCalls = 0
		}
		if err != nil || calls != wantCalls {
			t.Fatalf("beforeRun = %v: calls = %d, err = %v", beforeRun, calls, err)
		}
	}
}

func TestPacketBatchesError(t *testing.T) {
	wantErr := errors.New("run failed")
	for _, runErr := range []error{nil, wantErr} {
		calls := 0
		err := runPacketBatches(context.Background(), func(*ebpf.RunOptions) (uint32, error) {
			calls++
			return 1, runErr
		}, ebpf.RunOptions{}, packetBatchPlan{packets: 5, repeat: 2})
		if err == nil || calls != 1 {
			t.Fatalf("calls = %d, err = %v", calls, err)
		}
		if runErr != nil && !errors.Is(err, wantErr) {
			t.Fatalf("error not wrapped: %v", err)
		}
		if runErr == nil && !strings.Contains(err.Error(), "non-zero: 1") {
			t.Fatalf("unexpected return value error: %v", err)
		}
	}
}
