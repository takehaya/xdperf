package main

import "unsafe"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//go:wasmimport env host_log
func _host_log(level int32, msgPtr uint32, msgLen uint32)

//go:wasmimport env host_report_metric
func _host_report_metric(namePtr uint32, nameLen uint32, val float64, ts int64)

func log(level int, msg string) {
	ptr, size := StringToPtr(msg)
	_host_log(int32(level), ptr, size)
}
func report_metric(name string, val float64, ts int64) {
	ptr, size := StringToPtr(name)
	_host_report_metric(ptr, size, val, ts)
}

func StringToPtr(s string) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}
