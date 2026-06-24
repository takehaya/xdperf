package plugin

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero/api"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// maxPluginLogBytes bounds how much plugin-controlled text is logged per call,
// so a misbehaving plugin cannot flood the host log.
const maxPluginLogBytes = 4096

// makeLogFunc builds the host_log host function bound to lg. Plugin output is
// untrusted, so it is carried as a quoted zap field (escapes/control chars are
// neutralized by the encoder) and routed through the structured logger rather
// than printed raw to stdout — keeping --json output and level filtering intact.
func makeLogFunc(lg *zap.Logger) func(context.Context, api.Module, uint32, uint32, uint32) {
	return func(ctx context.Context, mod api.Module, level uint32, msgPtr, msgLen uint32) {
		data, ok := mod.Memory().Read(msgPtr, msgLen)
		if !ok {
			return
		}
		msg := string(data)
		if len(msg) > maxPluginLogBytes {
			msg = msg[:maxPluginLogBytes]
		}
		fields := []zap.Field{zap.Uint32("plugin_level", level), zap.String("msg", msg)}
		// Convention: 0=debug, 1=info, 2=warn, >=3=error.
		switch level {
		case 0:
			lg.Debug("plugin log", fields...)
		case 1:
			lg.Info("plugin log", fields...)
		case 2:
			lg.Warn("plugin log", fields...)
		default:
			lg.Error("plugin log", fields...)
		}
	}
}

// makeMetricFunc builds the host_report_metric host function bound to lg.
func makeMetricFunc(lg *zap.Logger) func(context.Context, api.Module, uint32, uint32, float64, int64) {
	return func(ctx context.Context, mod api.Module, namePtr, nameLen uint32, value float64, timestamp int64) {
		data, ok := mod.Memory().Read(namePtr, nameLen)
		if !ok {
			return
		}
		name := string(data)
		if len(name) > maxPluginLogBytes {
			name = name[:maxPluginLogBytes]
		}
		lg.Info("plugin metric",
			zap.String("name", name),
			zap.Float64("value", value),
			zap.Time("time", parseTimestamp(uint64(timestamp))),
		)
	}
}
func parseTimestamp(ts uint64) time.Time {
	nowNs := time.Now().UnixNano()
	switch {
	case ts > uint64(nowNs/100): // ns order
		return time.Unix(0, int64(ts))
	case ts > uint64(nowNs/100_000): // us order
		return time.Unix(0, int64(ts*1000))
	case ts > uint64(nowNs/100_000_000): // ms order
		return time.Unix(0, int64(ts*1_000_000))
	default: // sec order
		return time.Unix(int64(ts), 0)
	}
}

func neighborResolveFunc(ctx context.Context, mod api.Module, ipPtr uint32, ipLen uint32, ifaceNamePtr uint32, ifaceNameLen uint32, resultPtr uint32, resultLen uint32) uint32 {
	ip, ok := mod.Memory().Read(ipPtr, ipLen)
	if !ok {
		return 0
	}
	ifaceName, ok := mod.Memory().Read(ifaceNamePtr, ifaceNameLen)
	if !ok {
		return 0
	}

	macAddr := neighborResolveFuncImpl(string(ip), string(ifaceName))
	if macAddr == "" {
		return 0
	}

	macBytes := []byte(macAddr)
	if uint32(len(macBytes)) > resultLen {
		return 0
	}

	ok = mod.Memory().Write(resultPtr, macBytes)
	if !ok {
		return 0
	}

	return uint32(len(macBytes))
}

func neighborResolveFuncImpl(ip string, ifaceName string) string {
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return ""
	}

	family := netlink.FAMILY_V4
	if targetIP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	var linkIndex int
	if ifaceName != "" {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return ""
		}
		linkIndex = link.Attrs().Index
	}

	// check cache first
	if mac := lookupNeighborCache(linkIndex, family, targetIP); mac != "" {
		return mac
	}

	if ifaceName == "" {
		return "" // interface name required
	}

	// send neighbor solicitation
	if err := resolveNeighbor(linkIndex, family, targetIP); err != nil {
		return ""
	}

	// retry to lookup
	for i := 0; i < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		if mac := lookupNeighborCache(linkIndex, family, targetIP); mac != "" {
			return mac
		}
	}

	return ""
}

func lookupNeighborCache(linkIndex int, family int, targetIP net.IP) string {
	neighbors, err := netlink.NeighList(linkIndex, family)
	if err != nil {
		return ""
	}

	for _, neigh := range neighbors {
		if neigh.IP.Equal(targetIP) {
			if len(neigh.HardwareAddr) > 0 {
				return neigh.HardwareAddr.String()
			}
		}
	}
	return ""
}

func resolveNeighbor(linkIndex int, family int, targetIP net.IP) error {
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return err
	}
	ifaceName := link.Attrs().Name

	// Trigger neighbor (ARP/ND) resolution without shelling out to ping: send a
	// single UDP datagram bound to the egress interface. The kernel must resolve
	// the destination's L2 address before it can transmit, which populates the
	// neighbor cache that lookupNeighborCache then reads. Reachability is not
	// required — failures are best-effort and ignored.
	dialer := net.Dialer{
		Timeout: 1 * time.Second,
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}

	host := targetIP.String()
	if family == netlink.FAMILY_V6 && targetIP.IsLinkLocalUnicast() {
		host += "%" + ifaceName // link-local IPv6 needs a zone
	}

	// Port 9 (discard); the datagram only needs to leave the host to force resolution.
	conn, err := dialer.Dial("udp", net.JoinHostPort(host, "9"))
	if err != nil {
		return nil // best-effort: the cache lookup + retries handle failure
	}
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
	return nil
}
