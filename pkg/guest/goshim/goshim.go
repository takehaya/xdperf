package goshim

import (
	"encoding/json"
	"runtime"

	"github.com/mcuadros/go-defaults"
	"github.com/takehaya/xdperf/pkg/guest"
)

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorInitRequest
func _pluginGeneratorInitRequest(ptr, size uint32) (len uint32)
func PluginGeneratorInitRequest() guest.GeneratorInitRequest {
	rawMsg := GetBytes(func(ptr uint32, limit BufLimit) (len uint32) {
		return _pluginGeneratorInitRequest(ptr, limit)
	})

	var req guest.GeneratorInitRequest
	if err := json.Unmarshal(rawMsg, &req); err != nil {
		panic(err)
	}
	return req
}

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorInitResponse
func _pluginGeneratorInitResponse(ptr, size uint32)
func PluginGeneratorInitResponse(resp guest.GeneratorInitResponse) {
	rawMsg, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}

	ptr, size := BytesToPtr(rawMsg)
	_pluginGeneratorInitResponse(ptr, size)
	runtime.KeepAlive(rawMsg) // until ptr is no longer needed
}

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorProcessRequest
func _pluginGeneratorProcessRequest(ptr, size uint32) (len uint32)
func PluginGeneratorProcessRequest[T any]() T {
	rawMsg := GetBytes(func(ptr uint32, limit BufLimit) (len uint32) {
		return _pluginGeneratorProcessRequest(ptr, limit)
	})

	var req T
	defaults.SetDefaults(&req)
	if err := json.Unmarshal(rawMsg, &req); err != nil {
		panic(err)
	}
	return req
}

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorProcessResponse
func _pluginGeneratorProcessResponse(ptr, size uint32)
func PluginGeneratorProcessResponse(resp guest.GeneratorProcessResponse) {
	rawMsg, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}

	ptr, size := BytesToPtr(rawMsg)
	_pluginGeneratorProcessResponse(ptr, size)
	runtime.KeepAlive(rawMsg) // until ptr is no longer needed
}

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorCleanupRequest
func _pluginGeneratorCleanupRequest(ptr, size uint32) (len uint32)
func PluginGeneratorCleanupRequest() guest.GeneratorCleanupRequest {
	rawMsg := GetBytes(func(ptr uint32, limit BufLimit) (len uint32) {
		return _pluginGeneratorCleanupRequest(ptr, limit)
	})

	var req guest.GeneratorCleanupRequest
	if err := json.Unmarshal(rawMsg, &req); err != nil {
		panic(err)
	}
	return req
}

//go:wasmimport github.com/takehaya/xdperf/pkg/plugin/goshim pluginGeneratorCleanupResponse
func _pluginGeneratorCleanupResponse(ptr, size uint32)
func PluginGeneratorCleanupResponse(resp guest.GeneratorCleanupResponse) {
	rawMsg, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}

	ptr, size := BytesToPtr(rawMsg)
	_pluginGeneratorCleanupResponse(ptr, size)
	runtime.KeepAlive(rawMsg) // until ptr is no longer needed
}
