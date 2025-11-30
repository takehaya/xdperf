# xdperf WASM Plugin Quick Guide

This guide explains how to develop plugins based on `simpleudp.tinygo`.

## Overview
The host (xdperf) loads WASM modules and calls the following function handlers to obtain packet data.
By implementing a plugin, users can create custom packet generators.

## Required Exports
```go
//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }
```

The `plugin_process` function is where packet generation happens.
The host writes config/input/output buffers to WASM memory. The plugin reads input, generates JSON response, and writes it back.

## Directory Structure Example
```
plugins/simpleudp.tinygo/
  main.go      // Exports + logic
  config.go    // Request/Response definitions
  packet.go    // Packet generation
  go.mod       // Standalone module
```

## Key Types
See [pkg/guest/surface.go](https://github.com/takehaya/xdperf/tree/main/pkg/guest/surface.go) for the types that plugins should return.

## Host Imports
Several utility functions are exported from the host and can be used as an SDK.
Functions defined in `pkg/guest/api.go` can be called from plugins.

## Build (TinyGo)
```bash
cd plugins/simpleudp.tinygo
tinygo build -scheduler=none -target=wasip1 -buildmode=c-shared -o ../../out/bin/simpleudp.tinygo.wasm .
```
Key flags: `-target=wasip1` / `-buildmode=c-shared` / `-scheduler=none`.

Using Makefile from the project root:
```bash
# Build all plugins
make build-plugins

# Build a specific plugin
make simpleudp.tinygo
```

## Memory Helpers (Example)
```go
func BytesFrom(ptr, size uint32) []byte { return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size) }
func PtrToString(ptr, size uint32) string { return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size) }
func StringToPtr(s string) (uint32, uint32) { p := unsafe.Pointer(unsafe.StringData(s)); return uint32(uintptr(p)), uint32(len(s)) }
```
Don't forget to use `runtime.KeepAlive` to maintain lifetime of referenced data.
