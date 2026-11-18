package xdperf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/xdperf/pkg/probe"
	"github.com/vishvananda/netlink"
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

// attachXDP attaches prog to dev according to cfg.XDPMode.
// In auto mode it first attaches with no mode flag (the kernel picks native
// when the driver supports it) and retries in generic mode when that fails,
// e.g. on veth interfaces where the native attach can be rejected.
func (x *Xdperf) attachXDP(prog *ebpf.Program, dev *net.Interface) (link.Link, error) {
	mode, err := ParseXDPMode(x.cfg.XDPMode)
	if err != nil {
		return nil, err
	}
	opts := link.XDPOptions{
		Program:   prog,
		Interface: dev.Index,
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
				zap.String("device", dev.Name))
		}
		return l, nil
	}
	if mode != XDPModeAuto {
		return nil, fmt.Errorf("failed to attach XDP program in %s mode: %w", mode, err)
	}

	// The first attempt ran with no mode flag (kernel-preferred, usually
	// native); retry explicitly in generic mode.
	defaultErr := err
	opts.Flags = link.XDPGenericMode
	l, err = link.AttachXDP(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP program in both default and generic mode: %w", errors.Join(defaultErr, err))
	}
	x.Logger.Warn("default XDP attach failed; fell back to generic (SKB) mode with much lower performance",
		zap.String("device", dev.Name),
		zap.NamedError("default_attach_error", defaultErr))
	return l, nil
}

// checkLiveFrameTXSupport verifies that dev's driver implements native XDP
// (and therefore ndo_xdp_xmit), which BPF_F_TEST_XDP_LIVE_FRAMES requires to
// transmit XDP_TX frames. Devices like netkit or loopback accept a generic
// (SKB) XDP attach and let BPF_PROG_RUN succeed while xdp_do_redirect_frame
// silently drops every frame with -EOPNOTSUPP.
func checkLiveFrameTXSupport(dev *net.Interface) error {
	if dev == nil || dev.Name == "" {
		return fmt.Errorf("TX device is required")
	}
	res, err := probe.ProbeXDPSupport(dev.Name)
	if err != nil {
		return fmt.Errorf("failed to probe XDP support on %s: %w", dev.Name, err)
	}
	if !res.XDPDriverMode && (res.XDPFeatures != nil || res.AttachedMode == "") {
		if nlLink, lerr := netlink.LinkByIndex(dev.Index); lerr == nil && nlLink.Type() == "netkit" {
			return fmt.Errorf("device %s (netkit) does not support native XDP or ndo_xdp_xmit required for live-frame TX; run xdperf on the sending veth, SR-IOV VF, or physical NIC instead", dev.Name)
		}
		return fmt.Errorf("device %s does not support native XDP / ndo_xdp_xmit required for live-frame TX", dev.Name)
	}
	return nil
}
