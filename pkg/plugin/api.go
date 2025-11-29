package plugin

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/tetratelabs/wazero/api"
	"github.com/vishvananda/netlink"
)

func logFunc(ctx context.Context, mod api.Module, level uint32, msgPtr, msgLen uint32) {
	data, ok := mod.Memory().Read(msgPtr, msgLen)
	if !ok {
		return
	}
	logFuncImpl(level, string(data))
}
func logFuncImpl(level uint32, msg string) {
	fmt.Printf("[PLUGIN] [%d] %s\n", level, msg)
}

func metricFunc(ctx context.Context, mod api.Module, namePtr, nameLen uint32, value float64, timestamp int64) {
	data, ok := mod.Memory().Read(namePtr, nameLen)
	if !ok {
		return
	}
	metricFuncImpl(string(data), value, timestamp)
}

func metricFuncImpl(name string, value float64, timestamp int64) {
	t := parseTimestamp(uint64(timestamp))
	fmt.Printf("[METRIC] %s %.6f time=%s \n",
		name,
		value,
		t.Format(time.RFC3339Nano),
	)
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

	var cmd *exec.Cmd
	if family == netlink.FAMILY_V4 {
		// IPv4: ping でARP解決をトリガー
		cmd = exec.Command("ping", "-c", "1", "-W", "1", "-I", ifaceName, targetIP.String())
	} else {
		// IPv6: ping6 でNDP解決をトリガー
		cmd = exec.Command("ping", "-6", "-c", "1", "-W", "1", "-I", ifaceName, targetIP.String())
	}

	_ = cmd.Run() // エラーは無視（到達不能でもキャッシュに入る）
	return nil
}
