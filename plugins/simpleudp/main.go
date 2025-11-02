package main

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"runtime"
	"unsafe"

	"github.com/mcuadros/go-defaults"
)

// dummy main to satisfy Go compiler
func main() {}

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

//go:wasmexport plugin_init
func plugin_init(configPtr, configLen uint32) uint32 {
	msg := PtrToString(configPtr, configLen)
	log(1, "plugin initialized!: msg ->"+msg)
	return 0
}

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 {
	// read input
	in := BytesFrom(inputPtr, inputLen)
	if len(in) == 0 {
		log(3, "empty input")
		return -1
	}

	// decode input JSON
	var req GeneratorRequest
	defaults.SetDefaults(&req)
	if err := json.Unmarshal(in, &req); err != nil {
		log(3, "json unmarshal failed: "+err.Error())
		return -2
	}

	// show input
	log(1, "plugin_process called: count="+string(rune(req.Count)))
	log(1, "show input: "+string(in))

	// dummy ethernet packet as base_packet
	// dstMAC := [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	dstMAC := [6]byte{0x40, 0xA6, 0xB7, 0x82, 0xCD, 0xD8}

	// ペイロードの生成（指定サイズ）
	payload := make([]byte, req.PayloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// UDPパケットの構築
	packetBytes := BuildSimpleUDPPacket(
		[6]byte(req.DeviceMacAddr), dstMAC,
		req.SrcIP, req.DstIP,
		req.SrcPort, req.DstPort,
		payload,
	)

	// create response
	res := []GeneratorResponse{
		{
			Template: PacketTemplate{
				BasePacket: BasePacket{
					Data:   packetBytes,
					Length: uint16(len(packetBytes)),
				},
			},
			Metadata: Metadata{
				PacketCount: 1,
			},
		},
	}

	// marshal to JSON
	out, err := json.Marshal(res)
	if err != nil {
		log(3, "json marshal failed: "+err.Error())
		return -3
	}

	// write host memory
	if uint32(len(out)) > outputMaxLen {
		log(3, "output buffer too small")
		return -4
	}
	dst := BytesFrom(outputPtr, outputMaxLen)
	copy(dst, out)

	log(1, "response sent")
	return int32(len(out))
}

//go:wasmexport plugin_cleanup
func plugin_cleanup() {
	log(1, "Hello plugin cleanup")
}

// --- memutils.go ---
func BytesFrom(ptr, size uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// PtrToString returns a string from WebAssembly compatible numeric types
// representing its pointer and length.
func PtrToString(ptr uint32, size uint32) string {
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// StringToPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The returned pointer aliases the string hence the string must be kept alive
// until ptr is no longer needed.
func StringToPtr(s string) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}

// StringToLeakedPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The pointer is not automatically managed by TinyGo hence it must be freed by the host.
func StringToLeakedPtr(s string) (uint32, uint32) {
	size := C.ulong(len(s))
	ptr := unsafe.Pointer(C.malloc(size))
	copy(unsafe.Slice((*byte)(ptr), size), s)
	return uint32(uintptr(ptr)), uint32(size)
}
