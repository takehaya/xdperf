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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/xdperf/pkg/coreelf"
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

	pm, err := plugin.NewManager(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed init plugin manager: %w", err)
	}

	if err = pm.LoadPlugin(context.Background(), cfg.PluginName); err != nil {
		return nil, fmt.Errorf("failed load plugin: %w", err)
	}
	cleanupFnList = append(cleanupFnList, pm.Close)

	obj, err := coreelf.ReadCollection()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	cleanupFnList = append(cleanupFnList, func(ctx context.Context) error {
		return obj.Close()
	})

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

// TODO: あとで整理してpkg/pluginにから呼び出せるようにする
type GeneratorResponse struct {
	Template PacketTemplate `json:"template"`
	Metadata Metadata       `json:"metadata"`
}

type PacketTemplate struct {
	BasePacket BasePacket `json:"base_packet"`
}

type BasePacket struct {
	Data   []byte `json:"data"`
	Length uint16 `json:"length"`
}

type Metadata struct {
	PacketCount uint64 `json:"packet_count"`
	RatePPS     uint64 `json:"rate_pps"`
}

func (x *Xdperf) StartClient(ctx context.Context) error {
	x.Logger.Info("start client mode")

	resp, err := x.callPlugin(ctx)
	if err != nil {
		x.Logger.Error("failed to load plugin", zap.Error(err))
		return err
	}
	x.Logger.Info("plugin call successful", zap.Any("response", resp))

	entries, err := x.convToTxOverrideEntry(resp)
	if err != nil {
		x.Logger.Error("failed to convert to tx override entry", zap.Error(err))
		return err
	}
	x.Logger.Info("conversion to tx override entry successful", zap.Int("entry_count", len(entries)))

	for i, e := range entries {
		packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.Default)
		x.Logger.Info("constructed packet from entry", zap.Int("entry_index", i))
		for _, layer := range packet.Layers() {
			x.Logger.Info("packet layer", zap.String("layer_type", fmt.Sprintf("%T", layer)), zap.Any("layer", layer))
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
	x.Logger.Info("TX packet processing started")

	return nil
}

func (x *Xdperf) callPlugin(ctx context.Context) ([]*GeneratorResponse, error) {
	wasmPlugin, err := x.PluginManager.GetPlugin(x.cfg.PluginName)
	if err != nil {
		return nil, fmt.Errorf("failed get plugin: %w", err)
	}

	generator := plugin.NewGeneratorAdapter(x.cfg.PluginName, wasmPlugin)
	x.Logger.Info("testing simple plugin communication")

	// test input
	input := map[string]interface{}{
		"count":           x.cfg.Count,
		"device_mac_addr": x.Device.HardwareAddr,
	}

	x.Logger.Info("calling plugin", zap.Any("input", input))

	// call plugin
	outputBytes, err := generator.CallWithJSON(ctx, input)
	if err != nil {
		x.Logger.Error("CallWithJSON failed", zap.Error(err))
		return nil, fmt.Errorf("failed to call plugin (counter=%d): %w", x.cfg.Count, err)
	}
	x.Logger.Info("after CallWithJSON success")

	x.Logger.Info("received response",
		zap.Int("counter", x.cfg.Count),
		zap.Int("output_size", len(outputBytes)),
		zap.String("output", string(outputBytes)),
	)

	var response []*GeneratorResponse
	if err := json.Unmarshal(outputBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	x.Logger.Debug("parsed response",
		zap.Any("response", response),
	)

	return response, nil
}

func (x *Xdperf) convToTxOverrideEntry(resp []*GeneratorResponse) ([]*TxOverrideEntry, error) {
	var entries []*TxOverrideEntry
	for _, r := range resp {
		data := []byte(r.Template.BasePacket.Data)
		if len(data) < int(r.Template.BasePacket.Length) {
			return nil, fmt.Errorf("invalid packet length: data size %d < length %d", len(data), r.Template.BasePacket.Length)
		}
		entry := &TxOverrideEntry{
			Data:   data,
			Length: r.Template.BasePacket.Length,
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
	// TODO: カウント数 / スレッド数 にして送信しているが、あまりの部分については超えるようにケアする必要がある
	runOpts := &ebpf.RunOptions{
		Data:   in,
		Repeat: uint32(x.cfg.Count / x.cfg.Parallelism),
		Flags:  unix.BPF_F_TEST_XDP_LIVE_FRAMES,
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.ShowStats(ctx)
	prog := x.choiceTXBPFProgram()

	for i := range x.cfg.Parallelism {
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			go func() {
				defer p.Close()
				if err := x.run(ctx, cpu, p, runOpts); err != nil {
					fmt.Printf("error in run: %v\n", err)
				}
			}()
			<-ctx.Done()
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
