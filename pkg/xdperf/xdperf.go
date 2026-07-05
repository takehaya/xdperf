package xdperf

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/takehaya/xdperf/pkg/numa"
	"github.com/takehaya/xdperf/pkg/plugin"
	"github.com/takehaya/xdperf/pkg/telemetry"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type CancelFunc func(ctx context.Context) error
type Xdperf struct {
	Logger        *zap.Logger
	PluginManager *plugin.Manager
	cleanupFnList []CancelFunc
	bpfobjs       *coreelf.BpfObjects
	Device        *net.Interface
	cfg           Config
	bpfSpec       *ebpf.CollectionSpec
	cpus          []int      // resolved CPU list for workers
	pacing        *pacingSet // per-worker pacing-error recorders (sender only)

	ppsMu      sync.Mutex
	ppsSamples []uint64 // per-second TX pps deltas collected by ShowStats
}

func NewXdperf(cfg Config) (_ *Xdperf, err error) {
	var cleanupFnList []CancelFunc
	var xd *Xdperf
	// On any construction error the caller never gets a handle to Close(), so
	// release everything initialized up to that point here. Once xd exists it
	// owns the (possibly extended) cleanup list.
	defer func() {
		if err == nil {
			return
		}
		list := cleanupFnList
		if xd != nil {
			list = xd.cleanupFnList
		}
		for _, fn := range list {
			_ = fn(context.Background())
		}
	}()
	logger, cleanup, err := logger.NewLogger(cfg.LoggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed init logger: %w", err)
	}
	cleanupFnList = append(cleanupFnList, cleanup)
	var pm *plugin.Manager
	if cfg.Sender {
		managerOpts := []plugin.ManagerOption{plugin.WithLogger(logger)}
		if cfg.WasmCacheDir != "" {
			managerOpts = append(managerOpts, plugin.WithCacheDir(cfg.WasmCacheDir))
		}
		pm, err = plugin.NewManager(cfg.PluginPath, cfg.PluginConfig, cfg.PluginLanguage, managerOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed init plugin manager: %w", err)
		}

		if err = pm.LoadPlugin(context.Background(), cfg.PluginName); err != nil {
			return nil, fmt.Errorf("failed load plugin: %w", err)
		}
		cleanupFnList = append(cleanupFnList, pm.Close)
		logger.Info("xdperf wasm plugin loader initialized")
	}

	consts := map[string]interface{}{
		"swap_resp": func() uint32 {
			if cfg.Receiver && cfg.SwapResp {
				return 1
			}
			return 0
		}(),
	}

	// Calculate diff_map size based on mode. The kernel hard-caps the per-CPU
	// round-robin pool to coreelf.MaxDiffEntries (= MAX_DIFF_ENTRIES); sizing the
	// map beyond that just wastes entries the data plane never reads, so clamp here.
	var diffMapSize uint32
	if cfg.Sender {
		// Sender mode: size based on Count / Parallelism, clamped to the cap.
		diffMapSize = uint32(cfg.Count/uint64(cfg.Parallelism)) + 1
		if diffMapSize > coreelf.MaxDiffEntries {
			diffMapSize = coreelf.MaxDiffEntries
		}
	} else {
		// Receiver-only mode: minimal size since diff_map is not used.
		diffMapSize = 1
	}
	logger.Info("calculated diff_map size",
		zap.Uint32("diff_map_size", diffMapSize),
		zap.Uint32("max_diff_entries", coreelf.MaxDiffEntries),
	)

	obj, bpfSpec, err := coreelf.ReadCollection(consts, diffMapSize, cfg.DebugMode > 0)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	cleanupFnList = append(cleanupFnList, func(ctx context.Context) error {
		return obj.Close()
	})
	logger.Info("xdperf xdp code loader initialized")

	if cfg.Device == "" {
		return nil, fmt.Errorf("device is required")
	}
	dev, err := net.InterfaceByName(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("failed get device %s: %w", cfg.Device, err)
	}

	// Resolve CPU list based on NUMA topology
	cpus, err := numa.SelectCPUs(cfg.CPUMode, cfg.Parallelism, cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to select CPUs: %w", err)
	}
	if len(cpus) != cfg.Parallelism {
		cfg.Parallelism = len(cpus)
	}
	logger.Info("CPU selection",
		zap.String("mode", cfg.CPUMode),
		zap.Ints("selected_cpus", cpus),
		zap.Int("parallelism", cfg.Parallelism),
	)

	xd = &Xdperf{
		Logger:        logger,
		PluginManager: pm,
		cleanupFnList: cleanupFnList,
		bpfobjs:       obj,
		cfg:           cfg,
		Device:        dev,
		bpfSpec:       bpfSpec,
		cpus:          cpus,
	}

	if cfg.Sender {
		// Sized before workers start so the TX hot path never allocates; the
		// OTLP callback may read the recorders concurrently.
		xd.pacing = newPacingSet(len(cpus))
	}

	if cfg.OTLPEndpoint != "" {
		if err := xd.setupOTLPMetrics(); err != nil {
			return nil, fmt.Errorf("failed init otlp metrics: %w", err)
		}
	}

	return xd, nil
}

// setupOTLPMetrics wires the OTLP push exporter. Shutdown goes through
// cleanupFnList so the PeriodicReader's final flush runs on Close in both
// client and server mode.
func (x *Xdperf) setupOTLPMetrics() error {
	attrs, err := telemetry.ParseAttributes(x.cfg.OTLPAttributes)
	if err != nil {
		return err
	}
	mode := "client"
	switch {
	case x.cfg.Sender && x.cfg.Receiver:
		mode = "both"
	case x.cfg.Receiver:
		mode = "server"
	}
	// The gRPC exporter dials lazily, so Background is fine here even though
	// NewXdperf has no ctx parameter; reachability is not checked at setup.
	meter, shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Endpoint:   x.cfg.OTLPEndpoint,
		Interval:   x.cfg.OTLPInterval,
		Insecure:   x.cfg.OTLPInsecure,
		Attributes: attrs,
		Mode:       mode,
		Device:     x.cfg.Device,
		Version:    x.cfg.Version,
	}, x.Logger)
	if err != nil {
		return err
	}
	// Close() runs cleanupFnList front to back, so the shutdown (which
	// performs the final metrics flush and reads the BPF stats maps) must run
	// before the entry that closes the BPF objects — prepend, not append.
	x.cleanupFnList = append([]CancelFunc{shutdown}, x.cleanupFnList...)

	// Match the TrafficType selection in runTXPacket: the RX map is only
	// updated when both sender and receiver are enabled (XdpRx attached).
	ty := TrafficTypeTX
	switch {
	case x.cfg.Sender && x.cfg.Receiver:
		ty = TrafficTypeBoth
	case x.cfg.Receiver:
		ty = TrafficTypeRX
	}
	if err := x.registerMetrics(meter, ty); err != nil {
		return err
	}
	x.Logger.Info("otlp metrics exporter initialized",
		zap.String("endpoint", x.cfg.OTLPEndpoint),
		zap.Duration("interval", x.cfg.OTLPInterval),
	)
	return nil
}

func (x *Xdperf) StartClient(ctx context.Context) error {
	x.Logger.Info("start client mode")

	resp, err := x.callPlugin(ctx)
	if err != nil {
		x.Logger.Error("failed to load plugin", zap.Error(err))
		return err
	}
	x.Logger.Info("plugin call successful")

	x.Logger.Debug("plugin call successful for verbose logging", zap.Any("response", resp))

	// Initialize packet generation
	if err := x.initPacketGeneration(resp); err != nil {
		x.Logger.Error("failed to init packet generation", zap.Error(err))
		return err
	}

	if err := x.runTXPacket(ctx); err != nil {
		x.Logger.Error("failed to run TX packet", zap.Error(err))
		return err
	}

	return nil
}

// initPacketGeneration initializes packet generation from plugin response
// Uses base packet + diff entries approach for memory efficiency
func (x *Xdperf) initPacketGeneration(resp *guest.GeneratorProcessResponse) error {
	var bases []BasePacketInfo
	var diffEntries []DiffEntry
	var err error

	maxBasePackets := x.getBpfConstant("max_base_packets")

	// Bound the generated diff-entry pool to what the data plane can transmit
	// (coreelf.MaxDiffEntries per CPU). Without this, a large --count would
	// pre-allocate a correspondingly huge []DiffEntry on the host (OOM risk) while
	// the kernel only round-robins the first MaxDiffEntries/CPU anyway. The total
	// number of packets sent is governed separately by --count, not the pool size.
	genCount := int(x.cfg.Count)
	if maxGen := int(coreelf.MaxDiffEntries) * x.cfg.Parallelism; x.cfg.Parallelism > 0 && genCount > maxGen {
		x.Logger.Warn("requested count exceeds data-plane pool capacity, capping generated variant pool",
			zap.Uint64("requested_count", x.cfg.Count),
			zap.Int("max_pool_entries", maxGen),
			zap.Uint32("max_per_cpu", coreelf.MaxDiffEntries),
			zap.Int("parallelism", x.cfg.Parallelism),
		)
		genCount = maxGen
	}

	switch resp.TemplateType {
	case guest.GeneratorTemplateTypeVariable:
		bases, diffEntries, err = GenerateVariableEntries(*resp, genCount, maxBasePackets)
		if err != nil {
			return fmt.Errorf("failed to generate variable entries: %w", err)
		}
	case guest.GeneratorTemplateTypeRaw:
		bases, diffEntries, err = GenerateRawEntries(resp.RawPacketTemplate, genCount, maxBasePackets)
		if err != nil {
			return fmt.Errorf("failed to generate raw entries: %w", err)
		}
	default:
		return fmt.Errorf("unknown template type: %s", resp.TemplateType)
	}

	// Count total checksums across all bases
	totalChecksums := 0
	for _, b := range bases {
		totalChecksums += len(b.Checksums)
	}

	x.Logger.Info("packet entries generated",
		zap.String("template_type", string(resp.TemplateType)),
		zap.Int("num_bases", len(bases)),
		zap.Int("num_entries", len(diffEntries)),
		zap.Int("total_checksums", totalChecksums),
	)

	// Initialize BPF maps
	if err := x.initBpfMaps(bases, diffEntries); err != nil {
		return fmt.Errorf("failed to init BPF maps: %w", err)
	}

	return nil
}

func (x *Xdperf) callPlugin(ctx context.Context) (*guest.GeneratorProcessResponse, error) {
	wasmPlugin, err := x.PluginManager.GetPlugin(x.cfg.PluginName)
	if err != nil {
		return nil, fmt.Errorf("failed get plugin: %w", err)
	}

	generator := plugin.NewGeneratorAdapter(x.cfg.PluginName, wasmPlugin)
	x.Logger.Info("testing simple plugin communication")

	initReq := guest.GeneratorInitRequest{
		PluginConfig: []byte(x.cfg.PluginConfig),
	}
	initReqJSON, err := json.Marshal(initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal init request: %w", err)
	}

	if _, err := generator.Initialize(ctx, initReqJSON); err != nil {
		x.Logger.Error("plugin initialization failed", zap.Error(err))
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}
	x.Logger.Info("plugin initialized successfully")

	var pluginConfig map[string]interface{}
	if x.cfg.PluginConfig != "" {
		if err := json.Unmarshal([]byte(x.cfg.PluginConfig), &pluginConfig); err != nil {
			x.Logger.Error("failed to unmarshal plugin config", zap.Error(err))
			return nil, fmt.Errorf("failed to unmarshal plugin config: %w", err)
		}
	} else {
		pluginConfig = make(map[string]interface{})
	}

	// require base config for plugin
	pluginConfig["count"] = x.cfg.Count
	pluginConfig["device_mac_addr"] = x.Device.HardwareAddr
	pluginConfig["device_name"] = x.Device.Name

	x.Logger.Info("calling plugin", zap.Any("merged_config", pluginConfig))

	// call plugin
	resp, err := generator.GenerateTemplate(ctx, pluginConfig)
	if err != nil {
		x.Logger.Error("GenerateTemplate failed", zap.Error(err))
		return nil, fmt.Errorf("failed to call plugin (counter=%d): %w", x.cfg.Count, err)
	}
	x.Logger.Info("after GenerateTemplate success")

	x.Logger.Info("received response",
		zap.String("pattern", string(resp.VariablePacketTemplate.Pattern)),
		zap.Int("raw_packet_template_count", len(resp.RawPacketTemplate)),
		zap.Int("variable_packet_template_count", len(resp.VariablePacketTemplate.Variants)),
	)

	x.Logger.Debug("parsed response",
		zap.Any("response", resp),
	)

	return resp, nil
}

func (x *Xdperf) runTXPacket(ctx context.Context) error {
	in, err := x.BuildSamplePacket()
	if err != nil {
		return fmt.Errorf("failed to build sample packet: %w", err)
	}
	ttype := TrafficTypeTX
	rxprog := x.bpfobjs.XdpPassDummy
	if x.cfg.Sender && x.cfg.Receiver {
		ttype = TrafficTypeBoth
		rxprog = x.bpfobjs.XdpRx
	}
	// dummy XDP Prog attachment
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   rxprog,
		Interface: x.Device.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}
	defer l.Close()

	xdpmd := coreelf.XdpMd{
		DataEnd:        uint32(len(in)),
		IngressIfindex: uint32(x.Device.Index),
	}

	// Calculate batch parameters based on PPS setting
	repeatPerBatch, interval, totalBatches, batchSize := x.calculateBatchParams()

	runOpts := &ebpf.RunOptions{
		Data:      in,
		Repeat:    repeatPerBatch,
		Flags:     unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context:   xdpmd,
		BatchSize: batchSize,
	}

	if err := x.setupRTThrottling(); err != nil {
		return err
	}

	// Get NIC stats before sending (only if flag is set)
	var nicStatsBefore NICStats
	if x.cfg.ShowNICStats {
		nicStatsBefore = x.GetNICStats()
	}

	var wg sync.WaitGroup
	// Derive from the caller's context so a parent cancellation propagates to the
	// workers and the stats goroutine (previously rooted at context.Background(),
	// which silently dropped the parent's cancellation).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go x.ShowStats(ctx, ttype)
	prog := x.bpfobjs.XdpTx

	mode := "max speed"
	if x.cfg.Infinite {
		mode = "infinite"
	} else if x.cfg.PPS > 0 {
		mode = "rate limited"
	}
	x.Logger.Info("TX packet processing started ("+mode+")",
		zap.Int("parallelism", x.cfg.Parallelism),
		zap.Uint64("packet_pool_size", x.cfg.Count),
		zap.Uint64("target_pps", x.cfg.PPS),
		zap.Uint32("repeat_per_batch", repeatPerBatch),
		zap.Uint32("batch_size", batchSize),
		zap.Uint32("total_batches_per_cpu", totalBatches),
		zap.Duration("batch_interval", interval),
		zap.Bool("infinite_mode", x.cfg.Infinite),
		zap.String("sched_policy", x.cfg.SchedPolicy),
		zap.String("pacing_mode", x.cfg.PacingMode),
	)

	// Fail Fast: cancel all goroutines on first error
	var once sync.Once
	var firstErr error

	// Two-phase startup: every worker pins itself (and applies the RT policy)
	// first, reports its thread ID, and only starts transmitting once start is
	// closed. This creates the one point where all worker threads exist but no
	// packet has been sent — the sched_ext scheduler (--scx) must attach there,
	// with every worker TID already registered.
	ready := make(chan workerReady, len(x.cpus))
	start := make(chan struct{})

	for i, cpu := range x.cpus {
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(i, cpu int) {
			defer wg.Done()
			defer p.Close()
			if err := x.run(ctx, cpu, p, runOpts, interval, totalBatches, x.pacing.recorder(i), ready, start); err != nil {
				x.Logger.Error("error in run", zap.Int("cpu", cpu), zap.Error(err))
				// Fail Fast: cancel all other goroutines on first error
				once.Do(func() {
					firstErr = err
					cancel()
				})
			}
		}(i, cpu)
	}

	workerTIDs := make(map[int]int, len(x.cpus))
	barrierErr := func() error {
		for range x.cpus {
			select {
			case r := <-ready:
				if r.err != nil {
					return r.err
				}
				workerTIDs[r.cpu] = r.tid
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}()
	if barrierErr == nil {
		x.Logger.Debug("all workers pinned", zap.Any("tid_by_cpu", workerTIDs))
		close(start)
	} else {
		// Never close(start) on failure: the worker-side select between start
		// and ctx.Done is nondeterministic, and a max-speed worker slipping
		// into its loop after cancellation would still send the whole batch.
		x.Logger.Error("worker startup failed", zap.Error(barrierErr))
		cancel()
	}

	// Wait for either signal or all goroutines to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sig:
		if x.cfg.Infinite {
			x.Logger.Info("Received signal. Stopping infinite mode...")
		} else {
			x.Logger.Info("Received signal. Shutting down client...")
		}
	case <-done:
		if firstErr != nil {
			x.Logger.Error("Shutting down due to worker error...")
		} else {
			x.Logger.Info("All packets sent. Shutting down client...")
		}
	}
	cancel()
	wg.Wait()

	if firstErr == nil && barrierErr != nil {
		firstErr = barrierErr
	}

	// Show final statistics with NIC stats comparison
	x.ShowFinalStats(nicStatsBefore)

	if firstErr != nil {
		return fmt.Errorf("worker failed: %w", firstErr)
	}
	return nil
}

// calculateBatchParams calculates the repeat count per batch, interval between batches, total batches, and batch size.
// Returns (repeatPerBatch, interval, totalBatches, batchSize)
// - repeatPerBatch: number of times to repeat bpf_prog_run (0 means use batchSize for infinite mode)
// - interval: time between batches (0 means no rate limiting, run as fast as possible)
// - totalBatches: total number of batches to send per CPU (0 means infinite for infinite mode)
// - batchSize: number of packets per bpf_prog_run call (used in infinite mode with BatchSize feature)
func (x *Xdperf) calculateBatchParams() (uint32, time.Duration, uint32, uint32) {
	packetsPerCPU := uint32(x.cfg.Count / uint64(x.cfg.Parallelism))

	if x.cfg.Infinite {
		// Infinite mode: infinite sending at max speed using BatchSize feature
		return 1 << 20, 0, 0, x.cfg.BatchSize
	}

	if x.cfg.PPS == 0 {
		// Max speed: send all packets in one batch
		return packetsPerCPU, 0, 1, x.cfg.BatchSize
	}

	// PPS limited: calculate batch parameters
	ppsPerCPU := x.cfg.PPS / uint64(x.cfg.Parallelism)
	if ppsPerCPU == 0 {
		ppsPerCPU = 1
	}

	// Target batch interval balances pacing smoothness against per-batch
	// syscall overhead; --batch-interval overrides the 100ms default (smaller
	// = smoother traffic, more wakeups).
	targetInterval := x.cfg.BatchInterval
	if targetInterval <= 0 {
		targetInterval = defaultBatchInterval
	}
	packetsPerBatch := uint32(ppsPerCPU * uint64(targetInterval) / uint64(time.Second))

	if packetsPerBatch < 1 {
		packetsPerBatch = 1
	}
	if packetsPerBatch > packetsPerCPU {
		packetsPerBatch = packetsPerCPU
	}

	// Calculate total batches needed to send all packets
	totalBatches := packetsPerCPU / packetsPerBatch
	if totalBatches < 1 {
		totalBatches = 1
	}

	// Calculate interval based on packets per batch and target PPS
	// interval = packetsPerBatch / ppsPerCPU (in seconds)
	intervalNs := float64(packetsPerBatch) * float64(time.Second) / float64(ppsPerCPU)
	interval := time.Duration(intervalNs)

	// Floor the interval so the ticker path cannot degrade into a busy loop.
	// Busy pacing spins by design and only needs protection from a zero value.
	floor := time.Millisecond
	if x.cfg.PacingMode == PacingModeBusy {
		floor = 10 * time.Microsecond
	}
	if interval < floor {
		interval = floor
	}

	return packetsPerBatch, interval, totalBatches, 1
}

// workerReady is a worker's startup report: its pinned CPU, its OS thread ID
// (the kernel-side pid a sched_ext policy matches on), and any pin/policy
// error. The coordinator collects one per worker before releasing TX.
type workerReady struct {
	cpu int
	tid int
	err error
}

func (x *Xdperf) run(ctx context.Context, cpu int, xdpProg *ebpf.Program, runOpts *ebpf.RunOptions, interval time.Duration, totalBatches uint32, rec *pacingRecorder, ready chan<- workerReady, start <-chan struct{}) error {
	// Phase 1: pin this thread and apply the scheduling policy, then report
	// the thread ID and wait for the coordinator to release all workers at
	// once. The ready channel is buffered, so the send never blocks.
	runtime.LockOSThread()
	tid := unix.Gettid()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(tid, &cpuset); err != nil {
		err = fmt.Errorf("failed to set CPU affinity: %w", err)
		ready <- workerReady{cpu: cpu, tid: tid, err: err}
		return err
	}
	if err := x.applyWorkerSchedPolicy(); err != nil {
		ready <- workerReady{cpu: cpu, tid: tid, err: err}
		return err
	}
	ready <- workerReady{cpu: cpu, tid: tid}
	select {
	case <-start:
	case <-ctx.Done():
		return nil
	}

	// Phase 2: the TX loop for the selected mode.

	// Infinite mode: infinite loop until Ctrl-C
	if x.cfg.Infinite {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				ret, err := xdpProg.Run(runOpts)
				if err != nil {
					return fmt.Errorf("bpf_prog_run failed: %w", err)
				}
				if ret != 0 {
					return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
				}
			}
		}
	}

	// Unlimited mode: single batch execution
	if interval == 0 {
		ret, err := xdpProg.Run(runOpts)
		if err != nil {
			return fmt.Errorf("bpf_prog_run failed: %w", err)
		}
		if ret != 0 {
			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
		}
		return nil
	}

	if x.cfg.PacingMode == PacingModeBusy {
		return x.runBusyPaced(ctx, xdpProg, runOpts, interval, totalBatches, rec)
	}

	// PPS mode: rate-limited batch execution
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	last := time.Now()
	var sentBatches uint32
	for sentBatches < totalBatches {
		// Send batch
		ret, err := xdpProg.Run(runOpts)
		if err != nil {
			return fmt.Errorf("bpf_prog_run failed: %w", err)
		}
		if ret != 0 {
			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
		}
		sentBatches++

		// Wait for next tick (unless this was the last batch)
		if sentBatches < totalBatches {
			select {
			case <-ticker.C:
				// The gap between consecutive wakeups minus the interval is
				// the pacing error this run exists to measure: scheduling
				// delay plus timer coalescing (batches overrunning the
				// interval also surface here as missed ticks).
				now := time.Now()
				rec.record(now.Sub(last) - interval)
				last = now
			case <-ctx.Done():
				return nil
			}
		}
	}
	return nil
}

// runBusyPaced is the --pacing-mode=busy PPS loop: it spins on the clock
// toward absolute deadlines instead of sleeping on a ticker, trading one core
// of CPU for microsecond-level batch starts. Pair it with --sched-policy or
// --scx so the spin is not itself preempted.
func (x *Xdperf) runBusyPaced(ctx context.Context, xdpProg *ebpf.Program, runOpts *ebpf.RunOptions, interval time.Duration, totalBatches uint32, rec *pacingRecorder) error {
	next := time.Now()
	var sentBatches uint32
	for sentBatches < totalBatches {
		ret, err := xdpProg.Run(runOpts)
		if err != nil {
			return fmt.Errorf("bpf_prog_run failed: %w", err)
		}
		if ret != 0 {
			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
		}
		sentBatches++

		if sentBatches < totalBatches {
			next = next.Add(interval)
			for time.Now().Before(next) {
				if ctx.Err() != nil {
					return nil
				}
			}
			overshoot := time.Since(next)
			rec.record(overshoot)
			if overshoot > interval {
				// A batch overran its slot; rebase instead of bursting to
				// catch up, so the configured rate is a ceiling.
				next = time.Now()
			}
		}
	}
	return nil
}

func (x *Xdperf) Close() {
	for _, fn := range x.cleanupFnList {
		if err := fn(context.Background()); err != nil {
			x.Logger.Error("failed to cleanup", zap.Error(err))
		}
	}
	x.Logger.Info("xdperf cleanup completed")
}
