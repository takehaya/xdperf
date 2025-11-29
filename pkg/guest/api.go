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

func NeighborResolve(ip string, ifaceName string) ([]byte, error) {
	if len(ip) == 0 {
		return nil, fmt.Errorf("empty IP address")
	}
	if len(ifaceName) == 0 {
		return nil, fmt.Errorf("empty interface name")
	}
	ptr, size := StringToPtr(ip)
	ifacePtr, ifaceSize := StringToPtr(ifaceName)
	var resultBuf [32]byte // mac addr is "aa:bb:cc:dd:ee:ff" 17bytes
	resPtr := uint32(uintptr(unsafe.Pointer(&resultBuf[0])))
	n := _host_neighbor_resolve(ptr, size, ifacePtr, ifaceSize, resPtr, uint32(len(resultBuf)))
	if n > 0 {
		return resultBuf[:n], nil
	}
	return nil, fmt.Errorf("ARP lookup failed")
}
