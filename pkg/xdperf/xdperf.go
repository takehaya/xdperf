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
	"github.com/takehaya/xdperf/pkg/plugin"
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
}

func NewXdperf(cfg Config) (*Xdperf, error) {
	var cleanupFnList []CancelFunc
	logger, cleanup, err := logger.NewLogger(cfg.LoggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed init logger: %w", err)
	}
	cleanupFnList = append(cleanupFnList, cleanup)
	var pm *plugin.Manager
	if cfg.Sender {
		pm, err = plugin.NewManager(cfg.PluginPath, cfg.PluginConfig, cfg.PluginLanguage)
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
		"enable_xdpcap": func() uint32 {
			if cfg.EnableXdpcap {
				return 1
			}
			return 0
		}(),
	}

	// Calculate map sizes based on mode
	var mapSize uint32
	var diffMapSize uint32
	if cfg.Sender {
		// Sender mode: size based on Count / Parallelism
		sizePerCPU := uint32(cfg.Count/uint64(cfg.Parallelism)) + 1
		mapSize = sizePerCPU
		diffMapSize = sizePerCPU
		// Clamp to valid range [MinPacketEntry, MaxPacketEntry]
		if mapSize < coreelf.MinPacketEntry {
			mapSize = coreelf.MinPacketEntry
		}
		if mapSize > coreelf.MaxPacketEntry {
			mapSize = coreelf.MaxPacketEntry
		}
	} else {
		// Receiver-only mode: minimal size since tx_override_map and diff_map are not used
		mapSize = 1
		diffMapSize = 1
	}
	logger.Info("calculated map sizes",
		zap.Uint32("tx_override_map_size", mapSize),
		zap.Uint32("diff_map_size", diffMapSize),
	)

	obj, bpfSpec, err := coreelf.ReadCollection(consts, mapSize, diffMapSize)
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

	return &Xdperf{
		Logger:        logger,
		PluginManager: pm,
		cleanupFnList: cleanupFnList,
		bpfobjs:       obj,
		cfg:           cfg,
		Device:        dev,
		bpfSpec:       bpfSpec,
	}, nil
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

	// Get NIC stats before sending (only if flag is set)
	var nicStatsBefore NICStats
	if x.cfg.ShowNICStats {
		nicStatsBefore = x.GetNICStats()
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
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
	)

	// Fail Fast: cancel all goroutines on first error
	var once sync.Once
	var firstErr error

	for i := range x.cfg.Parallelism {
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			defer p.Close()
			if err := x.run(ctx, cpu, p, runOpts, interval, totalBatches); err != nil {
				x.Logger.Error("error in run", zap.Int("cpu", cpu), zap.Error(err))
				// Fail Fast: cancel all other goroutines on first error
				once.Do(func() {
					firstErr = err
					cancel()
				})
			}
		}(i)
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

	// Target batch interval: 100ms for good balance between precision and overhead
	const targetBatchIntervalMs = 100
	packetsPerBatch := uint32(ppsPerCPU * targetBatchIntervalMs / 1000)

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

	// Minimum interval to avoid busy loop
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	return packetsPerBatch, interval, totalBatches, 1
}

func (x *Xdperf) run(ctx context.Context, cpu int, xdpProg *ebpf.Program, runOpts *ebpf.RunOptions, interval time.Duration, totalBatches uint32) error {
	runtime.LockOSThread()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(unix.Gettid(), &cpuset); err != nil {
		return fmt.Errorf("failed to set CPU affinity: %v", err)
	}

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

	// PPS mode: rate-limited batch execution
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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
				// continue to next batch
			case <-ctx.Done():
				return nil
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
