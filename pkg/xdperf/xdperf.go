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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	}
	obj, err := coreelf.ReadCollection(consts)
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

	entries, err := x.convToTxOverrideEntry(resp)
	if err != nil {
		x.Logger.Error("failed to convert to tx override entry", zap.Error(err))
		return err
	}
	x.Logger.Info("conversion to tx override entry successful", zap.Int("entry_count", len(entries)))

	if x.cfg.DebugMode > 0 {
		x.Logger.Debug("debug mode is enabled, dumping packets...")
		for i, e := range entries {
			packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.Default)
			x.Logger.Debug("constructed packet from entry", zap.Int("entry_index", i))
			for _, layer := range packet.Layers() {
				x.Logger.Debug("packet layer", zap.String("layer_type", fmt.Sprintf("%T", layer)), zap.Any("layer", layer))
			}
		}
	}

	if err := x.initEbpfMap(entries); err != nil {
		x.Logger.Error("failed to init ebpf map", zap.Error(err))
		return err
	}
	x.Logger.Info("ebpf map initialization successful")

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
	pluginConfig["count"] = uint64(x.cfg.Count)
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

func (x *Xdperf) convToTxOverrideEntry(resp *guest.GeneratorProcessResponse) ([]*TxOverrideEntry, error) {
	switch resp.TemplateType {
	case guest.GeneratorTemplateTypeRaw:
		return x.convRawTemplate(resp.RawPacketTemplate)
	case guest.GeneratorTemplateTypeVariable:
		return x.convVariableTemplate(resp.VariablePacketTemplate, uint64(x.cfg.Count), x.cfg.Parallelism)
	default:
		return nil, fmt.Errorf("unknown template type: %s", resp.TemplateType)
	}
}

func (x *Xdperf) convRawTemplate(packets []guest.BasePacket) ([]*TxOverrideEntry, error) {
	var entries []*TxOverrideEntry
	for _, r := range packets {
		data := []byte(r.Data)
		if len(data) < int(r.Length) {
			return nil, fmt.Errorf("invalid packet length: data size %d < length %d", len(data), r.Length)
		}
		entry := &TxOverrideEntry{
			Data:   data,
			Length: r.Length,
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (x *Xdperf) choiceTXBPFProgram() *ebpf.Program {
	// For simplicity, we always use TX program here.
	// In the future, we may choose different programs based on the plugin response.
	return x.bpfobjs.XdpTx
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

	xdpmd := XdpMd{
		DataEnd:        uint32(len(in)),
		IngressIfindex: uint32(x.Device.Index),
	}
	runOpts := &ebpf.RunOptions{
		Data:    in,
		Repeat:  uint32(x.cfg.Count / x.cfg.Parallelism),
		Flags:   unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context: xdpmd,
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go x.ShowStats(ctx, ttype)
	prog := x.choiceTXBPFProgram()

	x.Logger.Info("TX packet processing started")

	for i := range x.cfg.Parallelism {
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			defer p.Close()
			if err := x.run(ctx, cpu, p, runOpts); err != nil {
				x.Logger.Error("error in run", zap.Int("cpu", cpu), zap.Error(err))
			}
		}(i)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	x.Logger.Info("Exec done. Shutting down client...")
	cancel()
	wg.Wait()

	return nil
}

func (x *Xdperf) run(ctx context.Context, cpu int, xdpProg *ebpf.Program, runOpts *ebpf.RunOptions) error {
	runtime.LockOSThread()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(unix.Gettid(), &cpuset); err != nil {
		return fmt.Errorf("failed to set CPU affinity: %v", err)
	}
	ret, err := xdpProg.Run(runOpts)
	if err != nil {
		return fmt.Errorf("bpf_prog_run failed: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
	}

	// interval := float64(time.Second) * float64(x.cfg.Count) * float64(x.cfg.Parallelism) / float64(x.cfg.PPS)
	// ticker := time.NewTicker(time.Duration(interval))
	// defer ticker.Stop()
	// for {
	// 	select {
	// 	case <-ticker.C:
	// 		ret, err := xdpProg.Run(runOpts)
	// 		if err != nil {
	// 			return fmt.Errorf("bpf_prog_run failed: %w", err)
	// 		}
	// 		if ret != 0 {
	// 			return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
	// 		}
	// 	case <-ctx.Done():
	// 		return nil
	// 	}
	// }
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
