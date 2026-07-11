package xdperf

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

// Pacing engines accepted by --pacing-mode for --pps runs.
const (
	PacingModeTicker = "ticker"
	PacingModeBusy   = "busy"
)

// pacingBuckets is the number of power-of-two histogram buckets. Bucket i
// holds samples whose nanosecond value has bit length i, i.e. [2^(i-1), 2^i),
// with bucket 0 for exact zero — 64 buckets cover any time.Duration.
const pacingBuckets = 64

// pacingRecorder accumulates one worker's pacing error: how far past its
// scheduled point each batch actually started. Only the owning worker writes,
// but the OTLP callback may read concurrently, hence the atomics. A nil
// recorder discards samples so callers need no branch.
type pacingRecorder struct {
	buckets [pacingBuckets]atomic.Uint64
	maxNs   atomic.Uint64
}

func (r *pacingRecorder) record(d time.Duration) {
	if r == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	ns := uint64(d)
	idx := bits.Len64(ns)
	if idx >= pacingBuckets {
		idx = pacingBuckets - 1
	}
	r.buckets[idx].Add(1)
	for {
		cur := r.maxNs.Load()
		if ns <= cur || r.maxNs.CompareAndSwap(cur, ns) {
			return
		}
	}
}

// pacingSet groups the per-worker recorders. It is sized once before the
// workers start so the hot path never allocates or locks.
type pacingSet struct {
	recorders []pacingRecorder
}

func newPacingSet(n int) *pacingSet {
	return &pacingSet{recorders: make([]pacingRecorder, n)}
}

func (s *pacingSet) recorder(i int) *pacingRecorder {
	if s == nil || i < 0 || i >= len(s.recorders) {
		return nil
	}
	return &s.recorders[i]
}

type pacingSummary struct {
	Count uint64
	P50   time.Duration
	P99   time.Duration
	Max   time.Duration
}

// summarize merges all workers and derives quantiles. A quantile is reported
// as the upper bound of the bucket it falls in, so it overestimates by at
// most 2x — precise enough to compare scheduling configurations.
func (s *pacingSet) summarize() pacingSummary {
	if s == nil {
		return pacingSummary{}
	}
	var merged [pacingBuckets]uint64
	var total, maxNs uint64
	for i := range s.recorders {
		r := &s.recorders[i]
		for b := range merged {
			merged[b] += r.buckets[b].Load()
		}
		if m := r.maxNs.Load(); m > maxNs {
			maxNs = m
		}
	}
	for _, c := range merged {
		total += c
	}
	if total == 0 {
		return pacingSummary{}
	}
	return pacingSummary{
		Count: total,
		P50:   bucketQuantile(&merged, total, 0.50),
		P99:   bucketQuantile(&merged, total, 0.99),
		Max:   time.Duration(maxNs),
	}
}

func bucketQuantile(buckets *[pacingBuckets]uint64, total uint64, q float64) time.Duration {
	target := uint64(math.Ceil(q * float64(total)))
	if target < 1 {
		target = 1
	}
	var cum uint64
	for i, c := range buckets {
		cum += c
		if cum >= target {
			if i == 0 {
				return 0
			}
			return time.Duration(uint64(1)<<uint(i) - 1)
		}
	}
	return time.Duration(math.MaxInt64)
}

// recordPPSSample appends one per-second TX packet delta from ShowStats.
func (x *Xdperf) recordPPSSample(v uint64) {
	x.ppsMu.Lock()
	x.ppsSamples = append(x.ppsSamples, v)
	x.ppsMu.Unlock()
}

type ppsStability struct {
	Samples int
	Mean    float64
	Stddev  float64
	CV      float64
	Min     uint64
	Max     uint64
}

// ppsStabilitySummary computes mean/stddev/CV over the per-second TX pps
// samples, trimming leading and trailing zero seconds (ramp-up and shutdown
// would otherwise dominate the variance). Needs at least two live samples.
func (x *Xdperf) ppsStabilitySummary() (ppsStability, bool) {
	x.ppsMu.Lock()
	samples := append([]uint64(nil), x.ppsSamples...)
	x.ppsMu.Unlock()

	lo, hi := 0, len(samples)
	for lo < hi && samples[lo] == 0 {
		lo++
	}
	for hi > lo && samples[hi-1] == 0 {
		hi--
	}
	samples = samples[lo:hi]
	if len(samples) < 2 {
		return ppsStability{}, false
	}

	st := ppsStability{Samples: len(samples), Min: samples[0], Max: samples[0]}
	var sum float64
	for _, v := range samples {
		sum += float64(v)
		if v < st.Min {
			st.Min = v
		}
		if v > st.Max {
			st.Max = v
		}
	}
	st.Mean = sum / float64(len(samples))
	var sq float64
	for _, v := range samples {
		d := float64(v) - st.Mean
		sq += d * d
	}
	st.Stddev = math.Sqrt(sq / float64(len(samples)))
	if st.Mean > 0 {
		st.CV = st.Stddev / st.Mean
	}
	return st, true
}
