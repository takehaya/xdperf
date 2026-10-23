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

	// The attach fallback only checks kernel live-frames API support.
	liveFrameLabel := "Live-frame TX capability"
	if result.XDPFeatures == nil {
		liveFrameLabel = "Live-frame API support (device TX not checked)"
	}
	lg.Info(liveFrameLabel,
		zap.Bool("live_frame_mode", result.LiveFrameMode),
	)

	// Summary
	if result.XDPSupported && result.LiveFrameMode {
		lg.Info("Summary: This device is fully compatible with xdperf")
	} else if result.XDPSupported && !result.LiveFrameMode {
		lg.Warn("Summary: XDP is supported, but live frame mode is not available",
			zap.String("note", "live-frame TX requires ndo_xdp_xmit and kernel live-frames support"),
		)
	} else {
		lg.Error("Summary: XDP is not supported on this device")
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
