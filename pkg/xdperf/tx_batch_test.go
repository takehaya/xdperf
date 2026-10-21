package xdperf

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"testing/synctest"
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
		batches    []uint64
		interval   time.Duration
	}{
		{name: "reported truncation", count: 25600, pps: 20000, workers: 1, packets: []uint64{25600}, repeats: []uint32{2000}, batches: []uint64{13}, interval: 100 * time.Millisecond},
		{name: "exact batches", count: 16000, pps: 20000, workers: 1, packets: []uint64{16000}, repeats: []uint32{2000}, batches: []uint64{8}, interval: 100 * time.Millisecond},
		{name: "worker and batch remainders", count: 25601, pps: 20000, workers: 3, packets: []uint64{8534, 8534, 8533}, repeats: []uint32{666, 666, 666}, batches: []uint64{13, 13, 13}, interval: 99900 * time.Microsecond},
		{name: "unlimited worker remainder", count: 101, workers: 3, packets: []uint64{34, 34, 33}, repeats: []uint32{34, 34, 33}, batches: []uint64{1, 1, 1}},
		{name: "PPS below workers", count: 7, pps: 2, workers: 4, packets: []uint64{2, 2, 2, 1}, repeats: []uint32{1, 1, 1, 1}, batches: []uint64{2, 2, 2, 1}, interval: 2 * time.Second},
		{name: "small count", count: 3, pps: 20000, workers: 1, packets: []uint64{3}, repeats: []uint32{3}, batches: []uint64{1}, interval: time.Millisecond},
		{name: "zero count", pps: 20000, workers: 1, packets: []uint64{0}, repeats: []uint32{1}, batches: []uint64{0}, interval: time.Millisecond},
		{name: "unlimited uint32 boundary", count: math.MaxUint32 + 7, workers: 1, packets: []uint64{math.MaxUint32 + 7}, repeats: []uint32{math.MaxUint32}, batches: []uint64{2}},
		{name: "PPS uint32 boundary", count: math.MaxUint32 + 7, pps: math.MaxUint64, workers: 1, packets: []uint64{math.MaxUint32 + 7}, repeats: []uint32{math.MaxUint32}, batches: []uint64{2}, interval: time.Millisecond},
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
				if plan.totalBatches() != tt.batches[slot] {
					t.Fatalf("slot %d: batches = %d, want %d", slot, plan.totalBatches(), tt.batches[slot])
				}
				wantInterval := tt.interval
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
				var sent, calls uint64
				// A sentinel catches a missing Repeat assignment in the send loop.
				opts := ebpf.RunOptions{Repeat: 99}
				err := runPacketBatches(context.Background(), func(got *ebpf.RunOptions) (uint32, error) {
					want := uint32(min(uint64(plan.repeat), plan.packets-sent))
					if got.Repeat == 0 || got.Repeat != want || got.BatchSize != wantBatchSize {
						t.Fatalf("run options = %+v, want repeat %d, batch size %d", got, want, wantBatchSize)
					}
					sent += uint64(got.Repeat)
					calls++
					return 0, nil
				}, opts, plan, nil)
				if err != nil || sent != plan.packets || calls != plan.totalBatches() {
					t.Fatalf("sent %d in %d calls, err %v; want %d in %d calls", sent, calls, err, plan.packets, plan.totalBatches())
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
	}, ebpf.RunOptions{}, plan, nil)
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
		// No tick will arrive: cancellation must interrupt the pacing wait.
		plan := packetBatchPlan{packets: 5, repeat: 2, batchSize: 1}
		err := runPacketBatches(ctx, func(*ebpf.RunOptions) (uint32, error) {
			calls++
			cancel()
			return 0, nil
		}, ebpf.RunOptions{}, plan, make(chan time.Time))
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
		}, ebpf.RunOptions{}, packetBatchPlan{packets: 5, repeat: 2}, nil)
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

func TestPacketBatchesPacing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ticks := make(chan time.Time)
		done := make(chan error, 1)
		var repeats []uint32
		go func() {
			done <- runPacketBatches(ctx, func(opts *ebpf.RunOptions) (uint32, error) {
				repeats = append(repeats, opts.Repeat)
				return 0, nil
			}, ebpf.RunOptions{}, packetBatchPlan{packets: 5, repeat: 2}, ticks)
		}()

		for batch, wantRepeat := range []uint32{2, 2, 1} {
			synctest.Wait()
			if len(repeats) != batch+1 || repeats[batch] != wantRepeat {
				t.Fatalf("batch %d: repeats = %v, want %d calls ending with %d", batch, repeats, batch+1, wantRepeat)
			}
			select {
			case err := <-done:
				if batch != 2 || err != nil {
					t.Fatalf("completed after batch %d with err %v", batch, err)
				}
			default:
				if batch == 2 {
					t.Fatal("waiting for a tick after the final batch")
				}
			}
			if batch < 2 {
				// Release exactly one batch; the loop must then wait again.
				ticks <- time.Now()
			}
		}
	})
}
