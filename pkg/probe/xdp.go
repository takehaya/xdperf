package probe

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	xdpAttachTimeout     = 2 * time.Second
	liveFrameTestTimeout = 3 * time.Second
	minTestPacketSize    = 64
)

type ProbeResult struct {
	DeviceName       string `json:"device"`
	XDPSupported     bool   `json:"xdp_supported"`
	XDPDriverMode    bool   `json:"xdp_driver_mode"`
	XDPGenericMode   bool   `json:"xdp_generic_mode"`
	XDPOffloadMode   bool   `json:"xdp_offload_mode"`
	LiveFrameMode    bool   `json:"live_frame_mode"`
	CurrentXDPProgID uint32 `json:"current_xdp_prog_id"`
	AttachedMode     string `json:"attached_mode"`
}

func getInterface(deviceName string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", deviceName, err)
	}
	return iface, nil
}

func attachXDPWithFallback(prog *ebpf.Program, ifindex int) (link.Link, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err == nil {
		return l, nil
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}
	return l, nil
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

	driverSupport, genericSupport, offloadSupport := probeXDPModes(iface.Index)
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

func probeXDPModes(ifindex int) (driver, generic, offload bool) {
	prog, cleanup, err := coreelf.LoadDummyProgram()
	if err != nil {
		return false, false, false
	}
	defer cleanup()

	driver = tryAttachXDPWithLinkTimeout(prog, ifindex, link.XDPDriverMode, xdpAttachTimeout)
	generic = tryAttachXDPWithLinkTimeout(prog, ifindex, link.XDPGenericMode, xdpAttachTimeout)
	// TODO: Offload mode probing requires hardware support
	offload = false

	return driver, generic, offload
}

func tryAttachXDPWithLinkTimeout(prog *ebpf.Program, ifindex int, flags link.XDPAttachFlags, timeout time.Duration) bool {
	resultCh := make(chan bool, 1)

	go func() {
		resultCh <- tryAttachXDPWithLink(prog, ifindex, flags)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-time.After(timeout):
		return false
	}
}

func tryAttachXDPWithLink(prog *ebpf.Program, ifindex int, flags link.XDPAttachFlags) bool {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     flags,
	})
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func ProbeLiveFrameMode(deviceName string) (bool, error) {
	iface, err := getInterface(deviceName)
	if err != nil {
		return false, err
	}

	prog, cleanup, err := coreelf.LoadDummyProgram()
	if err != nil {
		return false, fmt.Errorf("failed to load BPF program: %w", err)
	}
	defer cleanup()

	l, err := attachXDPWithFallback(prog, iface.Index)
	if err != nil {
		return false, err
	}
	defer l.Close()

	return runLiveFrameTest(prog, iface.Index)
}

func runLiveFrameTest(prog *ebpf.Program, ifindex int) (bool, error) {
	data := make([]byte, minTestPacketSize)

	xdpmd := coreelf.XdpMd{
		DataEnd:        uint32(len(data)),
		IngressIfindex: uint32(ifindex),
	}

	runOpts := &ebpf.RunOptions{
		Data:    data,
		Repeat:  1,
		Flags:   unix.BPF_F_TEST_XDP_LIVE_FRAMES,
		Context: xdpmd,
	}

	type result struct {
		supported bool
		err       error
	}
	resultCh := make(chan result, 1)

	go func() {
		_, err := prog.Run(runOpts)
		if err != nil {
			if isLiveFrameNotSupportedError(err) {
				resultCh <- result{supported: false, err: nil}
				return
			}
			resultCh <- result{supported: false, err: fmt.Errorf("failed to run BPF program: %w", err)}
			return
		}
		resultCh <- result{supported: true, err: nil}
	}()

	select {
	case res := <-resultCh:
		return res.supported, res.err
	case <-time.After(liveFrameTestTimeout):
		return false, fmt.Errorf("timeout while probing live frame mode")
	}
}

func ProbeAll(deviceName string) (*ProbeResult, error) {
	result, err := ProbeXDPSupport(deviceName)
	if err != nil {
		return nil, err
	}

	if result.XDPSupported {
		liveFrameSupported, err := ProbeLiveFrameMode(deviceName)
		if err != nil {
			// Live frame mode probe failed, but XDP is still supported
			result.LiveFrameMode = false
		} else {
			result.LiveFrameMode = liveFrameSupported
		}
	}

	return result, nil
}
