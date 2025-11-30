//go:build wasm

package guest

import (
	"fmt"
	"runtime"
	"unsafe"
)

//go:wasmimport env host_log
func _host_log(level uint32, msgPtr uint32, msgLen uint32)

func Log(level uint32, msg string) {
	if len(msg) == 0 {
		return
	}
	ptr, size := StringToPtr(msg)
	_host_log(level, ptr, size)
	runtime.KeepAlive(msg)
}

//go:wasmimport env host_report_metric
func _host_report_metric(namePtr uint32, nameLen uint32, value float64, timestamp int64)

func ReportMetric(name string, value float64, timestamp int64) {
	if len(name) == 0 {
		return
	}
	ptr, size := StringToPtr(name)
	_host_report_metric(ptr, size, value, timestamp)
	runtime.KeepAlive(name)
}

//go:wasmimport env host_neighbor_resolve
func _host_neighbor_resolve(ipPtr uint32, ipLen uint32, ifaceNamePtr uint32, ifaceNameLen uint32, resultPtr uint32, resultLen uint32) uint32

func NeighborResolve(ip string, ifaceName string) (string, error) {
	if len(ip) == 0 {
		return "", fmt.Errorf("empty IP address")
	}
	if len(ifaceName) == 0 {
		return "", fmt.Errorf("empty interface name")
	}
	ptr, size := StringToPtr(ip)
	ifacePtr, ifaceSize := StringToPtr(ifaceName)
	var resultBuf [32]byte // mac addr is "aa:bb:cc:dd:ee:ff" 17bytes
	resPtr := uint32(uintptr(unsafe.Pointer(&resultBuf[0])))
	n := _host_neighbor_resolve(ptr, size, ifacePtr, ifaceSize, resPtr, uint32(len(resultBuf)))
	if n == 0 {
		return "", fmt.Errorf("ARP lookup failed")
	}

	macStr := string(resultBuf[:n])
	return macStr, nil
}

func ParseMAC(s string) ([]byte, error) {
	if len(s) != 17 {
		return nil, fmt.Errorf("invalid MAC address length: %d", len(s))
	}

	mac := make([]byte, 6)
	for i := 0; i < 6; i++ {
		hi := hexToByte(s[i*3])
		lo := hexToByte(s[i*3+1])
		if hi == 0xFF || lo == 0xFF {
			return nil, fmt.Errorf("invalid hex character in MAC address")
		}
		mac[i] = (hi << 4) | lo

		if i < 5 && s[i*3+2] != ':' {
			return nil, fmt.Errorf("invalid MAC address separator")
		}
	}
	return mac, nil
}

func hexToByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF // invalid
	}
}
