package probe

type XDPAttachMode uint8

const (
	XDPAttachModeNone   XDPAttachMode = 0
	XDPAttachModeDriver XDPAttachMode = 1
	XDPAttachModeSKB    XDPAttachMode = 2
	XDPAttachModeHW     XDPAttachMode = 3
	XDPAttachModeMulti  XDPAttachMode = 4
)

func (m XDPAttachMode) String() string {
	switch m {
	case XDPAttachModeNone:
		return "none"
	case XDPAttachModeDriver:
		return "driver"
	case XDPAttachModeSKB:
		return "generic"
	case XDPAttachModeHW:
		return "offload"
	case XDPAttachModeMulti:
		return "multi"
	default:
		return "unknown"
	}
}
