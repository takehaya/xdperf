//go:build wasm

package guest

import (
	"runtime"
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
