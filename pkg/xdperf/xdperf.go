package xdperf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/takehaya/xdperf/pkg/numa"
	"github.com/takehaya/xdperf/pkg/plugin"
	"github.com/takehaya/xdperf/pkg/telemetry"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type CancelFunc func(ctx context.Context) error
type Xdperf struct {
	Logger          *zap.Logger
	PluginManager   *plugin.Manager
	cleanupFnList   []CancelFunc
	bpfobjs         *coreelf.BpfObjects
	Device          *net.Interface
	RxDevice        *net.Interface // RX attach target; == Device unless --rx-device splits it off
	cfg             Config
	bpfSpec         *ebpf.CollectionSpec
	tcpVariantBytes []uint64 // validated per-flow targets
	pluginResponse  *guest.GeneratorProcessResponse
	mixed           *mixedPlan
	otlpMeter       metric.Meter
	summary         *runSummary
	cpus            []int // resolved CPU list for workers
}

// calculateDiffMapSize requires a validated config with positive Parallelism.
func calculateDiffMapSize(cfg Config, resp *guest.GeneratorProcessResponse) uint32 {
	if !cfg.Sender {
		return 1
	}
	if resp != nil && resp.TemplateType == guest.GeneratorTemplateTypeVariable && len(resp.VariablePacketTemplate.Variants) > 0 {
		tcpOnly := true
		for _, variant := range resp.VariablePacketTemplate.Variants {
			if variant.Kind != "tcp_flow" {
				tcpOnly = false
				break
			}
		}
		if tcpOnly {
			return 1
		}
	}
	// Clamp before adding the spare entry and narrowing, avoiding both uint64
	// overflow at MaxUint64 and uint32 truncation for large packet budgets.
	return uint32(min(cfg.Count/uint64(cfg.Parallelism), uint64(coreelf.MaxDiffEntries)-1) + 1)
}

// calculatePacketPoolSize requires a validated config with positive Parallelism.
// The generated pool is bounded independently of the uint64 send budget.
func calculatePacketPoolSize(cfg Config) int {
	maxPoolEntries := uint64(coreelf.MaxDiffEntries) * uint64(cfg.Parallelism)
	return int(min(cfg.Count, maxPoolEntries))
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

		loadCtx, cancelLoad := context.WithTimeout(context.Background(), 30*time.Second)
		closePlugin := func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return pm.Close(ctx)
		}
		cleanupFnList = append(cleanupFnList, closePlugin)
		err = pm.LoadPlugin(loadCtx, cfg.PluginName)
		cancelLoad()
		if err != nil {
			return nil, fmt.Errorf("failed load plugin: %w", err)
		}
		logger.Info("xdperf wasm plugin loader initialized")
	}

	if cfg.Device == "" {
		return nil, fmt.Errorf("device is required")
	}
	dev, err := net.InterfaceByName(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("failed get device %s: %w", cfg.Device, err)
	}

	// Generate once before loading maps so TCP-only plugins do not allocate an
	// unused packet diff pool. Union/bounds validation remains in StartClient.
	var resp *guest.GeneratorProcessResponse
	if cfg.Sender {
		client := &Xdperf{Logger: logger, PluginManager: pm, cfg: cfg, Device: dev}
		resp, err = client.callPlugin(context.Background())
		if err != nil {
			return nil, err
		}
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
	diffMapSize := calculateDiffMapSize(cfg, resp)
	logger.Info("calculated diff_map size",
		zap.Uint32("diff_map_size", diffMapSize),
		zap.Uint32("max_diff_entries", coreelf.MaxDiffEntries),
	)

	// The --tcp-server flow table is an LRU hash preallocated at load time:
	// size it only in that mode so the other modes do not pay for it.
	tcpSrvFlows := uint32(1)
	if cfg.TCPServer {
		tcpSrvFlows = uint32(cfg.TCPMaxConns)
	}
	obj, bpfSpec, err := coreelf.ReadBaseCollectionWithSizes(consts,
		map[string]uint32{"diff_map": diffMapSize, "tcp_srv_flow_map": tcpSrvFlows}, cfg.DebugMode > 0)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	cleanupFnList = append(cleanupFnList, func(ctx context.Context) error {
		return obj.Close()
	})
	logger.Info("xdperf xdp code loader initialized")

	rxdev := dev
	if cfg.RxDevice != "" && cfg.RxDevice != cfg.Device {
		rxdev, err = net.InterfaceByName(cfg.RxDevice)
		if err != nil {
			return nil, fmt.Errorf("failed get rx device %s: %w", cfg.RxDevice, err)
		}
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
	if cfg.Sender {
		warnVethQueues(logger, cfg.Device, len(cpus))
	}

	xd = &Xdperf{
		Logger:         logger,
		PluginManager:  pm,
		pluginResponse: resp,
		cleanupFnList:  cleanupFnList,
		bpfobjs:        obj,
		cfg:            cfg,
		Device:         dev,
		RxDevice:       rxdev,
		bpfSpec:        bpfSpec,
		cpus:           cpus,
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
	// Only export xdperf.rx_device when the RX attach really is split off;
	// --rx-device equal to --device behaves exactly like the single-device case.
	rxDevice := ""
	if x.RxDevice.Index != x.Device.Index {
		rxDevice = x.RxDevice.Name
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
		RxDevice:   rxDevice,
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
	x.otlpMeter = meter
	x.Logger.Info("otlp metrics exporter initialized",
		zap.String("endpoint", x.cfg.OTLPEndpoint),
		zap.Duration("interval", x.cfg.OTLPInterval),
	)
	return nil
}

func (x *Xdperf) StartClient(ctx context.Context) error {
	x.Logger.Info("start client mode")

	resp := x.pluginResponse
	x.Logger.Info("plugin call successful")

	x.Logger.Debug("plugin call successful for verbose logging", zap.Any("response", resp))

	if err := x.prepareMixed(resp); err != nil {
		return err
	}
	if err := x.cfg.validateRunBounds(x.mixed); err != nil {
		return err
	}
	if x.mixed != nil {
		if err := coreelf.LoadMixedProgramsWithFeatures(x.bpfobjs, x.bpfSpec, x.mixed.features); err != nil {
			return err
		}
		if x.otlpMeter != nil {
			if err := x.registerMixedRXMetrics(x.otlpMeter); err != nil {
				return err
			}
		}
		return x.runTCP(ctx)
	}
	if x.cfg.TCPFlowReport != "" {
		return fmt.Errorf("--tcp-flow-report requires TCP flow variants")
	}

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
	genCount := calculatePacketPoolSize(x.cfg)
	if uint64(genCount) < x.cfg.Count {
		x.Logger.Warn("requested count exceeds data-plane pool capacity, capping generated variant pool",
			zap.Uint64("requested_count", x.cfg.Count),
			zap.Int("max_pool_entries", genCount),
			zap.Uint32("max_per_cpu", coreelf.MaxDiffEntries),
			zap.Int("parallelism", x.cfg.Parallelism),
		)
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
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
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

	out, err := generator.Initialize(ctx, initReqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize plugin: %w", err)
	}
	var initialized guest.GeneratorInitResponse
	if err := json.Unmarshal(out, &initialized); err != nil {
		return nil, fmt.Errorf("plugin init response: %w", err)
	}
	if !initialized.Success {
		return nil, fmt.Errorf("plugin initialization failed")
	}
	x.Logger.Info("plugin initialized successfully")

	var pluginConfig map[string]interface{}
	if x.cfg.PluginConfig != "" {
		dec := json.NewDecoder(strings.NewReader(x.cfg.PluginConfig))
		dec.UseNumber()
		if err := dec.Decode(&pluginConfig); err != nil {
			x.Logger.Error("failed to unmarshal plugin config", zap.Error(err))
			return nil, fmt.Errorf("failed to unmarshal plugin config: %w", err)
		}
		if err := dec.Decode(new(interface{})); err != io.EOF {
			return nil, fmt.Errorf("trailing data in plugin config")
		}
	} else {
		pluginConfig = make(map[string]interface{})
	}

	if pluginConfig == nil {
		return nil, fmt.Errorf("plugin config must be an object")
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
	if x.RxDevice.Index != x.Device.Index {
		// Split mode: xdp_rx counts on the dedicated RX device, while the TX
		// device keeps a dummy program so its own veth XDP_TX path stays alive.
		lrx, err := x.attachXDP(rxprog, x.RxDevice)
		if err != nil {
			return err
		}
		defer lrx.Close()
		rxprog = x.bpfobjs.XdpPassDummy
	}
	// dummy XDP Prog attachment
	l, err := x.attachXDP(rxprog, x.Device)
	if err != nil {
		return err
	}
	defer l.Close()

	xdpmd := coreelf.XdpMd{
		DataEnd:        uint32(len(in)),
		IngressIfindex: uint32(x.Device.Index),
	}

	// The first worker has the largest share when Count is not divisible by
	// Parallelism. Each worker gets its own plan below.
	logPlan := calculatePacketBatchPlan(x.cfg, 0)

	runOpts := ebpf.RunOptions{
		Data:    in,
		Flags:   unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context: xdpmd,
	}

	// Get NIC stats before sending (only if flag is set)
	var nicStatsBefore NICStats
	if x.cfg.ShowNICStats {
		nicStatsBefore = x.GetNICStats()
	}

	x.beginSummary()
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
		zap.Uint32("repeat_per_batch_slot0", logPlan.repeat),
		zap.Uint32("batch_size", logPlan.batchSize),
		zap.Uint64("total_batches_slot0", logPlan.totalBatches()),
		zap.Duration("batch_interval_slot0", logPlan.interval),
		zap.Bool("infinite_mode", x.cfg.Infinite),
	)

	// Fail Fast: cancel all goroutines on first error
	var once sync.Once
	var firstErr error

	for slot, cpu := range x.cpus {
		plan := calculatePacketBatchPlan(x.cfg, slot)
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			defer p.Close()
			if err := x.run(ctx, cpu, p, runOpts, plan); err != nil {
				x.Logger.Error("error in run", zap.Int("cpu", cpu), zap.Error(err))
				// Fail Fast: cancel all other goroutines on first error
				once.Do(func() {
					firstErr = err
					cancel()
				})
			}
		}(cpu)
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

	// Show final statistics with NIC stats comparison
	x.ShowFinalStats(nicStatsBefore)

	if firstErr != nil {
		return fmt.Errorf("worker failed: %w", firstErr)
	}
	return x.writeSummary()
}

func (x *Xdperf) run(ctx context.Context, cpu int, xdpProg *ebpf.Program, runOpts ebpf.RunOptions, plan packetBatchPlan) error {
	runtime.LockOSThread()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(unix.Gettid(), &cpuset); err != nil {
		return fmt.Errorf("failed to set CPU affinity: %v", err)
	}
	var ticks <-chan time.Time
	if plan.interval > 0 {
		ticker := time.NewTicker(plan.interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	return runPacketBatches(ctx, xdpProg.Run, runOpts, plan, ticks)
}

func (x *Xdperf) Close() {
	for _, fn := range x.cleanupFnList {
		if err := fn(context.Background()); err != nil {
			x.Logger.Error("failed to cleanup", zap.Error(err))
		}
	}
	x.Logger.Info("xdperf cleanup completed")
}
