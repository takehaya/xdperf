package probe

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/urfave/cli"
	"go.uber.org/zap"
)

func RunProbe(ctx *cli.Context) error {
	deviceName := ctx.String("device")
	if deviceName == "" {
		return fmt.Errorf("device name is required")
	}

	jsonOutput := ctx.Bool("json")

	// Initialize logger
	lg, cleanup, err := logger.NewLogger(logger.Config{
		JSON:    jsonOutput,
		NoColor: jsonOutput,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() { _ = cleanup(context.Background()) }()

	if !jsonOutput {
		lg.Info("Probing XDP capabilities", zap.String("device", deviceName))
	}

	result, err := ProbeAll(deviceName)
	if err != nil {
		return fmt.Errorf("probe failed: %w", err)
	}

	// Environment checks look at the same worker CPUs the run command would
	// pick for this cpu-mode/parallelism.
	result.Environment = ProbeEnv(deviceName, ctx.String("cpu-mode"), ctx.Int("parallelism"))

	if jsonOutput {
		return printProbeResultJSON(result)
	}

	printProbeResultWithLogger(lg, result)
	return nil
}

func printProbeResultWithLogger(lg *zap.Logger, result *ProbeResult) {
	lg.Info("Device", zap.String("name", result.DeviceName))

	// XDP Support
	lg.Info("XDP Support",
		zap.Bool("supported", result.XDPSupported),
		zap.Bool("driver_mode", result.XDPDriverMode),
		zap.Bool("generic_mode", result.XDPGenericMode),
		zap.Bool("offload_mode", result.XDPOffloadMode),
	)

	if result.CurrentXDPProgID > 0 {
		lg.Info("Currently Attached XDP Program",
			zap.Uint32("prog_id", result.CurrentXDPProgID),
			zap.String("mode", result.AttachedMode),
		)
	}

	// BPF_PROG_RUN Support
	lg.Info("BPF_PROG_RUN Support",
		zap.Bool("live_frame_mode", result.LiveFrameMode),
	)

	if env := result.Environment; env != nil {
		printEnvWithLogger(lg, env)
	}

	// Summary
	if result.XDPSupported && result.LiveFrameMode {
		lg.Info("Summary: This device is fully compatible with xdperf")
	} else if result.XDPSupported && !result.LiveFrameMode {
		lg.Warn("Summary: XDP is supported, but live frame mode is not available",
			zap.String("note", "xdperf requires kernel 5.18+ for BPF_PROG_RUN live packet mode"),
		)
	} else {
		lg.Error("Summary: XDP is not supported on this device")
	}
}

// printEnvWithLogger renders the environment checks: informational lines for
// capabilities, warnings for conditions known to add TX jitter.
func printEnvWithLogger(lg *zap.Logger, env *EnvResult) {
	lg.Info("Kernel", zap.String("release", env.KernelRelease))

	se := env.SchedExt
	fields := []zap.Field{
		zap.Bool("available", se.Available),
		zap.Bool("scx_usable", se.ScxUsable),
	}
	if se.State != "" {
		fields = append(fields, zap.String("state", se.State))
	}
	if se.RootOps != "" {
		fields = append(fields, zap.String("running_scheduler", se.RootOps))
	}
	if se.Reason != "" {
		fields = append(fields, zap.String("reason", se.Reason))
	}
	lg.Info("sched_ext (--scx)", fields...)

	if env.CPUSelectionError != "" {
		lg.Warn("CPU selection failed", zap.String("error", env.CPUSelectionError))
	} else if len(env.SelectedCPUs) > 0 {
		lg.Info("Worker CPUs (as run would select)", zap.Ints("cpus", env.SelectedCPUs))
	}

	if env.RTRuntimeUs != "" && env.RTRuntimeUs != "-1" {
		lg.Warn("RT throttling active: --sched-policy workers will stall periodically",
			zap.String("sched_rt_runtime_us", env.RTRuntimeUs),
			zap.String("hint", "use --disable-rt-throttling on the run, or write -1 to /proc/sys/kernel/sched_rt_runtime_us"),
		)
	}

	for cpu, gov := range env.CPUGovernors {
		if gov != "performance" {
			lg.Warn("CPU frequency governor is not \"performance\"",
				zap.Int("cpu", cpu), zap.String("governor", gov),
				zap.String("hint", "frequency transitions add latency jitter"),
			)
		}
	}

	if env.IRQBalanceRunning {
		lg.Warn("irqbalance is running: it may move device IRQs onto worker CPUs")
	}
	if env.IsolCPUs != "" {
		lg.Info("Boot-time CPU isolation", zap.String("isolcpus", env.IsolCPUs))
	}
	if env.NohzFull != "" {
		lg.Info("Tickless CPUs", zap.String("nohz_full", env.NohzFull))
	}
	if env.RCUNocbs != "" {
		lg.Info("RCU callback offload", zap.String("rcu_nocbs", env.RCUNocbs))
	}

	overlapped := 0
	for _, irq := range env.DeviceIRQs {
		if irq.Overlaps {
			overlapped++
			lg.Warn("Device IRQ affinity overlaps a worker CPU",
				zap.Int("irq", irq.IRQ),
				zap.String("name", irq.Name),
				zap.Ints("cpus", irq.CPUs),
				zap.String("hint", "steer the IRQ elsewhere or pick other CPUs via --cpu-mode"),
			)
		}
	}
	if len(env.DeviceIRQs) > 0 && overlapped == 0 {
		lg.Info("Device IRQs stay off the worker CPUs", zap.Int("irqs", len(env.DeviceIRQs)))
	}
}

func printProbeResultJSON(result *ProbeResult) error {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}
