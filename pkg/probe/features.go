package probe

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Values from include/uapi/linux/netdev.h (Linux 6.3+).
const (
	netdevCmdDevGet       = 1
	netdevADevIfindex     = 1
	netdevADevXDPFeatures = 3
	netdevXDPActBasic     = 1 << 0
	netdevXDPActNdoXmit   = 1 << 2
	netdevXDPActHWOffload = 1 << 4
)

var errNetdevUnavailable = errors.New("netdev generic netlink family unavailable")

func getXDPFeatures(ifindex int) (uint64, error) {
	family, err := netlink.GenlFamilyGet("netdev")
	if errors.Is(err, unix.ENOENT) {
		return 0, errNetdevUnavailable
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get netdev family: %w", err)
	}

	req := nl.NewNetlinkRequest(int(family.ID), 0)
	// nl.Genlmsg in netlink v1.3.1 leaves the two reserved bytes uninitialized.
	req.AddRawData([]byte{netdevCmdDevGet, uint8(family.Version), 0, 0})
	req.AddRawData(nl.NewRtAttr(netdevADevIfindex, nl.Uint32Attr(uint32(ifindex))).Serialize())
	msgs, err := req.Execute(unix.NETLINK_GENERIC, family.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to get netdev XDP features: %w", err)
	}
	if len(msgs) != 1 {
		return 0, fmt.Errorf("expected one netdev response, got %d", len(msgs))
	}
	return parseXDPFeatures(msgs[0])
}

func parseXDPFeatures(msg []byte) (uint64, error) {
	if len(msg) < nl.SizeofGenlmsg {
		return 0, fmt.Errorf("short netdev response")
	}
	attrs, err := nl.ParseRouteAttr(msg[nl.SizeofGenlmsg:])
	if err != nil {
		return 0, fmt.Errorf("invalid netdev attributes: %w", err)
	}
	for _, attr := range attrs {
		if attr.Attr.Type&nl.NLA_TYPE_MASK == netdevADevXDPFeatures {
			if len(attr.Value) != 8 {
				return 0, fmt.Errorf("invalid netdev XDP features length: %d", len(attr.Value))
			}
			return nl.NativeEndian().Uint64(attr.Value), nil
		}
	}
	return 0, fmt.Errorf("netdev response missing XDP features")
}

func (r *ProbeResult) setXDPFeatures(features uint64) {
	r.XDPFeatures = &features
	r.XDPDriverMode = features&netdevXDPActBasic != 0
	r.XDPGenericMode = true
	r.XDPOffloadMode = features&netdevXDPActHWOffload != 0
	// Live-frame XDP_TX redirects to the same device through ndo_xdp_xmit.
	r.LiveFrameMode = features&netdevXDPActNdoXmit != 0
	r.XDPSupported = true
}
