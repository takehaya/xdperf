package xdperf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// XDPMode is the XDP attach mode selectable via --xdp-mode.
type XDPMode uint8

const (
	XDPModeAuto    XDPMode = iota // kernel-preferred attach, fall back to generic on failure
	XDPModeNative                 // driver (native) mode only, fail if unsupported
	XDPModeGeneric                // generic (SKB) mode only
)

func (m XDPMode) String() string {
	switch m {
	case XDPModeAuto:
		return "auto"
	case XDPModeNative:
		return "native"
	case XDPModeGeneric:
		return "generic"
	default:
		return "unknown"
	}
}

// ParseXDPMode parses a --xdp-mode flag value. An empty string means the
// default (auto) so programmatically-built configs work without Normalize.
func ParseXDPMode(s string) (XDPMode, error) {
	switch s {
	case "", "auto":
		return XDPModeAuto, nil
	case "native":
		return XDPModeNative, nil
	case "generic":
		return XDPModeGeneric, nil
	default:
		return XDPModeAuto, fmt.Errorf("invalid --xdp-mode %q (must be auto, native, or generic)", s)
	}
}

// attachXDP attaches prog to the target device according to cfg.XDPMode.
// In auto mode it first attaches with no mode flag (the kernel picks native
// when the driver supports it) and retries in generic mode when that fails,
// e.g. on veth interfaces where the native attach can be rejected.
func (x *Xdperf) attachXDP(prog *ebpf.Program) (link.Link, error) {
	mode, err := ParseXDPMode(x.cfg.XDPMode)
	if err != nil {
		return nil, err
	}
	opts := link.XDPOptions{
		Program:   prog,
		Interface: x.Device.Index,
	}
	switch mode {
	case XDPModeNative:
		opts.Flags = link.XDPDriverMode
	case XDPModeGeneric:
		opts.Flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(opts)
	if err == nil {
		if mode == XDPModeGeneric {
			x.Logger.Info("XDP attached in generic (SKB) mode; expect much lower performance than native mode",
				zap.String("device", x.Device.Name))
		}
		return l, nil
	}
	if mode != XDPModeAuto {
		return nil, fmt.Errorf("failed to attach XDP program in %s mode: %w", mode, err)
	}

	nativeErr := err
	opts.Flags = link.XDPGenericMode
	l, err = link.AttachXDP(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP program in both native and generic mode: %w", errors.Join(nativeErr, err))
	}
	x.Logger.Warn("native XDP attach failed; fell back to generic (SKB) mode with much lower performance",
		zap.String("device", x.Device.Name),
		zap.NamedError("native_error", nativeErr))
	return l, nil
}
