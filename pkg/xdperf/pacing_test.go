package xdperf

import (
	"testing"
	"time"
)

func TestPacingRecorderSummarize(t *testing.T) {
	set := newPacingSet(2)

	// Worker 0: 90 samples at ~1µs, worker 1: 10 samples at ~1ms.
	for i := 0; i < 90; i++ {
		set.recorder(0).record(1 * time.Microsecond)
	}
	for i := 0; i < 10; i++ {
		set.recorder(1).record(1 * time.Millisecond)
	}

	s := set.summarize()
	if s.Count != 100 {
		t.Fatalf("Count = %d, want 100", s.Count)
	}
	// Quantiles report the bucket upper bound, i.e. at most 2x the true value.
	if s.P50 < 1*time.Microsecond || s.P50 >= 2*time.Microsecond {
		t.Errorf("P50 = %v, want in [1µs, 2µs)", s.P50)
	}
	if s.P99 < 1*time.Millisecond || s.P99 >= 2*time.Millisecond {
		t.Errorf("P99 = %v, want in [1ms, 2ms)", s.P99)
	}
	if s.Max != 1*time.Millisecond {
		t.Errorf("Max = %v, want 1ms", s.Max)
	}
}

func TestPacingRecorderNilSafe(t *testing.T) {
	var set *pacingSet
	set.recorder(0).record(time.Second) // must not panic
	if s := set.summarize(); s.Count != 0 {
		t.Errorf("nil set summarize Count = %d, want 0", s.Count)
	}

	nonNil := newPacingSet(1)
	nonNil.recorder(5).record(time.Second) // out of range → discarded
	if s := nonNil.summarize(); s.Count != 0 {
		t.Errorf("out-of-range recorder should discard, got Count = %d", s.Count)
	}
}

func TestPacingRecorderNegativeClamp(t *testing.T) {
	set := newPacingSet(1)
	set.recorder(0).record(-time.Second)
	s := set.summarize()
	if s.Count != 1 || s.P50 != 0 || s.Max != 0 {
		t.Errorf("negative sample should clamp to zero bucket, got %+v", s)
	}
}

func TestPPSStabilitySummary(t *testing.T) {
	x := &Xdperf{}
	// Leading/trailing zeros (ramp-up and shutdown seconds) must be trimmed.
	for _, v := range []uint64{0, 0, 100, 110, 90, 100, 0} {
		x.recordPPSSample(v)
	}
	st, ok := x.ppsStabilitySummary()
	if !ok {
		t.Fatal("expected a summary")
	}
	if st.Samples != 4 {
		t.Errorf("Samples = %d, want 4 (zeros trimmed)", st.Samples)
	}
	if st.Mean != 100 {
		t.Errorf("Mean = %v, want 100", st.Mean)
	}
	if st.Min != 90 || st.Max != 110 {
		t.Errorf("Min/Max = %d/%d, want 90/110", st.Min, st.Max)
	}
	if st.CV <= 0 {
		t.Errorf("CV = %v, want > 0", st.CV)
	}
}

func TestPPSStabilitySummaryTooFewSamples(t *testing.T) {
	x := &Xdperf{}
	x.recordPPSSample(0)
	x.recordPPSSample(100)
	if _, ok := x.ppsStabilitySummary(); ok {
		t.Error("single live sample must not produce a summary")
	}
}

func TestCalculateBatchParamsBatchInterval(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		wantRepeat   uint32
		wantInterval time.Duration
	}{
		{
			name:         "default_100ms",
			cfg:          Config{Count: 1000000, Parallelism: 1, PPS: 100000},
			wantRepeat:   10000,
			wantInterval: 100 * time.Millisecond,
		},
		{
			name:         "custom_10ms",
			cfg:          Config{Count: 1000000, Parallelism: 1, PPS: 100000, BatchInterval: 10 * time.Millisecond},
			wantRepeat:   1000,
			wantInterval: 10 * time.Millisecond,
		},
		{
			name: "ticker_floor_1ms",
			// 100 pps with 1ms target → 1 packet per batch → 10ms natural
			// interval; but 1000 pps at 100µs target floors the ticker to 1ms.
			cfg:          Config{Count: 100000, Parallelism: 1, PPS: 10000, BatchInterval: 100 * time.Microsecond},
			wantRepeat:   1,
			wantInterval: time.Millisecond,
		},
		{
			name:         "busy_floor_allows_sub_ms",
			cfg:          Config{Count: 100000, Parallelism: 1, PPS: 10000, BatchInterval: 100 * time.Microsecond, PacingMode: PacingModeBusy},
			wantRepeat:   1,
			wantInterval: 100 * time.Microsecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &Xdperf{cfg: tt.cfg}
			repeat, interval, _, batchSize := x.calculateBatchParams()
			if repeat != tt.wantRepeat {
				t.Errorf("repeatPerBatch = %d, want %d", repeat, tt.wantRepeat)
			}
			if interval != tt.wantInterval {
				t.Errorf("interval = %v, want %v", interval, tt.wantInterval)
			}
			if batchSize != 1 {
				t.Errorf("batchSize = %d, want 1 in PPS mode", batchSize)
			}
		})
	}
}

func TestConfigValidateSchedPacing(t *testing.T) {
	base := func() Config {
		c := Config{
			Device:      "eth0",
			Sender:      true,
			PluginName:  "simpleudp.tinygo",
			Parallelism: 1,
			Count:       100,
		}
		c.Normalize()
		return c
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "defaults_pass",
			mutate: func(c *Config) {},
		},
		{
			name:   "fifo_valid",
			mutate: func(c *Config) { c.SchedPolicy = SchedPolicyFIFO; c.SchedPriority = 50 },
		},
		{
			name:   "rr_valid",
			mutate: func(c *Config) { c.SchedPolicy = SchedPolicyRR; c.SchedPriority = 1 },
		},
		{
			name:    "unknown_policy",
			mutate:  func(c *Config) { c.SchedPolicy = "deadline" },
			wantErr: true,
		},
		{
			name:    "priority_out_of_range",
			mutate:  func(c *Config) { c.SchedPolicy = SchedPolicyFIFO; c.SchedPriority = 100 },
			wantErr: true,
		},
		{
			name:    "priority_zero_with_policy",
			mutate:  func(c *Config) { c.SchedPolicy = SchedPolicyFIFO; c.SchedPriority = 0 },
			wantErr: true,
		},
		{
			name:    "disable_rt_throttling_requires_policy",
			mutate:  func(c *Config) { c.DisableRTThrottling = true },
			wantErr: true,
		},
		{
			name:   "disable_rt_throttling_with_policy",
			mutate: func(c *Config) { c.SchedPolicy = SchedPolicyFIFO; c.SchedPriority = 50; c.DisableRTThrottling = true },
		},
		{
			name:    "busy_requires_pps",
			mutate:  func(c *Config) { c.PacingMode = PacingModeBusy },
			wantErr: true,
		},
		{
			name:   "busy_with_pps",
			mutate: func(c *Config) { c.PacingMode = PacingModeBusy; c.PPS = 1000 },
		},
		{
			name:    "unknown_pacing_mode",
			mutate:  func(c *Config) { c.PacingMode = "spin" },
			wantErr: true,
		},
		{
			name: "recv_only_rejects_sched_policy",
			mutate: func(c *Config) {
				c.Sender = false
				c.Receiver = true
				c.SchedPolicy = SchedPolicyFIFO
			},
			wantErr: true,
		},
		{
			name: "recv_only_rejects_busy_pacing",
			mutate: func(c *Config) {
				c.Sender = false
				c.Receiver = true
				c.PacingMode = PacingModeBusy
			},
			wantErr: true,
		},
		{
			name: "recv_only_defaults_pass",
			mutate: func(c *Config) {
				c.Sender = false
				c.Receiver = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
