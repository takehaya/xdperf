package main

import (
	"runtime"
	"unsafe"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

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

// activeBuffers は、ホスト(Wazero)に貸し出しているメモリが
// GoのGCによって勝手に回収されないように保持しておくためのマップです。
var activeBuffers = make(map[uint32][]byte)

//go:wasmexport plugin_malloc
func plugin_malloc(size uint32) uint32 {
	// 1. 指定されたサイズでGoのバイト配列を作成
	buf := make([]byte, size)

	// 2. その配列の先頭ポインタを取得
	// (サイズ0の場合は安全策としてnil扱いにしても良いが、通常makeで確保される)
	if size == 0 {
		return 0
	}
	ptr := unsafe.Pointer(&buf[0])
	uintPtr := uint32(uintptr(ptr))

	// 3. マップに保存してGCを防ぐ
	activeBuffers[uintPtr] = buf

	// 4. ポインタアドレスをホストに返す
	return uintPtr
}

//go:wasmexport plugin_free
func plugin_free(ptr uint32) {
	// マップから削除することで、GoのGCが回収できるようにする
	delete(activeBuffers, ptr)
}
