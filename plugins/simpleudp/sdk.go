package main

import "runtime"

//go:wasmimport env host_log
func host_log(level uint32, msgPtr uint32, msgLen uint32)

func log(level uint32, msg string) {
	if len(msg) == 0 {
		return
	}
	ptr, size := StringToPtr(msg)
	host_log(level, ptr, size)
	runtime.KeepAlive(msg)
}

//go:wasmimport env host_report_metric
func host_report_metric(namePtr uint32, nameLen uint32, value float64, timestamp int64)

func report_metric(name string, value float64, timestamp int64) {
	if len(name) == 0 {
		return
	}
	ptr, size := StringToPtr(name)
	host_report_metric(ptr, size, value, timestamp)
	runtime.KeepAlive(name)
}
