package probe

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const minTestPacketSize = 64

type ProbeResult struct {
	DeviceName       string  `json:"device"`
	XDPSupported     bool    `json:"xdp_supported"`
	XDPDriverMode    bool    `json:"xdp_driver_mode"`
	XDPGenericMode   bool    `json:"xdp_generic_mode"`
	XDPOffloadMode   bool    `json:"xdp_offload_mode"`
	LiveFrameMode    bool    `json:"live_frame_mode"`
	CurrentXDPProgID uint32  `json:"current_xdp_prog_id"`
	AttachedMode     string  `json:"attached_mode"`
	XDPFeatures      *uint64 `json:"xdp_features,omitempty"`
}

func getInterface(deviceName string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", deviceName, err)
	}
	return iface, nil
}

func isLiveFrameNotSupportedError(err error) bool {
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "not supported") ||
		strings.Contains(errStr, "invalid argument") ||
		strings.Contains(errStr, "operation not permitted")
}

func ProbeXDPSupport(deviceName string) (*ProbeResult, error) {
	result := &ProbeResult{
		DeviceName: deviceName,
	}

	iface, err := getInterface(deviceName)
	if err != nil {
		return nil, err
	}

	nlLink, err := netlink.LinkByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get link info: %w", err)
	}

	attrs := nlLink.Attrs()
	if attrs.Xdp != nil && attrs.Xdp.Attached {
		result.CurrentXDPProgID = attrs.Xdp.ProgId
		result.XDPSupported = true
		attachMode := XDPAttachMode(attrs.Xdp.AttachMode)
		result.AttachedMode = attachMode.String()
		switch attachMode {
		case XDPAttachModeDriver:
			result.XDPDriverMode = true
		case XDPAttachModeSKB:
			result.XDPGenericMode = true
		case XDPAttachModeHW:
			result.XDPOffloadMode = true
		}
	}

	features, err := getXDPFeatures(iface.Index)
	if err == nil {
		result.setXDPFeatures(features)
		return result, nil
	}
	if !errors.Is(err, errNetdevUnavailable) {
		return nil, err
	}

	driverSupport, genericSupport, offloadSupport, err := probeXDPModes(iface.Index)
	if err != nil {
		return nil, err
	}
	if driverSupport {
		result.XDPDriverMode = true
	}
	if genericSupport {
		result.XDPGenericMode = true
	}
	if offloadSupport {
		result.XDPOffloadMode = true
	}

	result.XDPSupported = result.XDPDriverMode || result.XDPGenericMode || result.XDPOffloadMode

	return result, nil
}

func probeXDPModes(ifindex int) (driver, generic, offload bool, err error) {
	prog, cleanup, err := coreelf.LoadDummyProgram()
	if err != nil {
		return false, false, false, err
	}
	defer cleanup()

	// Wait for each attach and detach to finish before trying the next mode.
	driver, err = tryAttachXDPWithLink(prog, ifindex, link.XDPDriverMode)
	if err != nil {
		return false, false, false, err
	}
	generic, err = tryAttachXDPWithLink(prog, ifindex, link.XDPGenericMode)
	return driver, generic, false, err
}

func tryAttachXDPWithLink(prog *ebpf.Program, ifindex int, flags link.XDPAttachFlags) (bool, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     flags,
	})
	if err != nil {
		return false, nil
	}
	if err := l.Close(); err != nil {
		return false, fmt.Errorf("failed to detach probe program: %w", err)
	}
	return true, nil
}

func ProbeLiveFrameMode(deviceName string) (bool, error) {
	iface, err := getInterface(deviceName)
	if err != nil {
		return false, err
	}

	features, err := getXDPFeatures(iface.Index)
	if err == nil {
		return features&netdevXDPActNdoXmit != 0, nil
	}
	if !errors.Is(err, errNetdevUnavailable) {
		return false, err
	}
	return probeLegacyLiveFrameMode()
}

func probeLegacyLiveFrameMode() (bool, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return false, err
	}
	// DROP on loopback tests the live-frames API without transmitting or injecting a packet.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1), // XDP_DROP
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return false, fmt.Errorf("failed to load BPF program: %w", err)
	}
	defer prog.Close()

	data := make([]byte, minTestPacketSize)
	_, err = prog.Run(&ebpf.RunOptions{
		Data:    data,
		Repeat:  1,
		Flags:   unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context: coreelf.XdpMd{DataEnd: uint32(len(data))},
	})
	if err != nil {
		if isLiveFrameNotSupportedError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to run BPF program: %w", err)
	}
	return true, nil
}

func ProbeAll(deviceName string) (*ProbeResult, error) {
	result, err := ProbeXDPSupport(deviceName)
	if err != nil {
		return nil, err
	}

	if result.XDPFeatures == nil && result.XDPSupported {
		liveFrameSupported, err := probeLegacyLiveFrameMode()
		if err != nil {
			// Live frame mode probe failed, but XDP is still supported
			result.LiveFrameMode = false
		} else {
			result.LiveFrameMode = liveFrameSupported
		}
	}

	return result, nil
}
