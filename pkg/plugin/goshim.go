package plugin

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/stealthrocket/wazergo"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	pkgname = "github.com/takehaya/xdperf/pkg/plugin/goshim"

	// Host function exports
	pluginGeneratorInitRequest     = "pluginGeneratorInitRequest"
	pluginGeneratorInitResponse    = "pluginGeneratorInitResponse"
	pluginGeneratorProcessRequest  = "pluginGeneratorProcessRequest"
	pluginGeneratorProcessResponse = "pluginGeneratorProcessResponse"
	pluginGeneratorCleanupRequest  = "pluginGeneratorCleanupRequest"
	pluginGeneratorCleanupResponse = "pluginGeneratorCleanupResponse"

	getShutdownRequested = "getShutdownRequested"
)

// writeBytesIfUnderLimit writes bytes to memory if they fit within the limit
func writeBytesIfUnderLimit(memory api.Memory, bytes []byte, buf, bufLimit uint32) uint32 {
	if uint32(len(bytes)) > bufLimit {
		return 0
	}
	if !memory.Write(buf, bytes) {
		return 0
	}
	return uint32(len(bytes))
}

// stackKey is the key used to store the stack in the context
type stackKey struct{}

// GeneratorStack holds the data being passed between the host and the guest
type GeneratorStack struct {
	GeneratorInitRequest     []byte
	GeneratorInitResponse    []byte
	GeneratorProcessRequest  []byte
	GeneratorProcessResponse []byte
	GeneratorCleanupRequest  []byte
	GeneratorCleanupResponse []byte

	InitResponseChan    chan []byte
	ProcessResponseChan chan []byte
	CleanupResponseChan chan []byte

	RequestedShutdown atomic.Bool
}

// createContextWithStack creates a new context with a Stack
func createContextWithStack(ctx context.Context, stack *GeneratorStack) context.Context {
	return context.WithValue(ctx, stackKey{}, stack)
}

// paramsFromContext retrieves the GeneratorStack from the context
func paramsFromContext(ctx context.Context) *GeneratorStack {
	return ctx.Value(stackKey{}).(*GeneratorStack)
}

func instantiateHostModule(ctx context.Context, runtime wazero.Runtime) (api.Module, error) {
	return runtime.NewHostModuleBuilder(pkgname).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginInitRequestFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorInitRequest).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginInitResponseFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorInitResponse).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginProcessRequestFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorProcessRequest).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginProcessResponseFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorProcessResponse).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginCleanupRequestFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorCleanupRequest).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(pluginCleanupResponseFn), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
		WithParameterNames("buf", "buf_limit").Export(pluginGeneratorCleanupResponse).
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(getShutdownRequestedFn), []api.ValueType{}, []api.ValueType{api.ValueTypeI32}).
		Export(getShutdownRequested).
		Instantiate(ctx)
}

type byteSlice interface{ ~[]byte }

func makeWriteHandler[T byteSlice](getter func(*GeneratorStack) T) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		buf := uint32(stack[0])
		bufLimit := uint32(stack[1])

		bs := getter(paramsFromContext(ctx))
		stack[0] = uint64(writeBytesIfUnderLimit(mod.Memory(), []byte(bs), buf, bufLimit))
	}
}

func makeReadHandler[T byteSlice](setter func(*GeneratorStack, T)) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		buf := uint32(stack[0])
		size := uint32(stack[1])

		resp, ok := mod.Memory().Read(buf, size)
		if !ok {
			panic("out of memory reading result metrics") // Bug: caller passed a length outside memory
		}

		setter(paramsFromContext(ctx), T(resp))
	}
}

var pluginInitRequestFn = makeWriteHandler(func(s *GeneratorStack) []byte {
	return s.GeneratorInitRequest
})

var pluginInitResponseFn = makeReadHandler(func(s *GeneratorStack, b []byte) {
	s.GeneratorInitResponse = b
	if s.InitResponseChan != nil {
		s.InitResponseChan <- b
	}
})

var pluginProcessRequestFn = makeWriteHandler(func(s *GeneratorStack) []byte {
	return s.GeneratorProcessRequest
})

var pluginProcessResponseFn = makeReadHandler(func(s *GeneratorStack, b []byte) {
	s.GeneratorProcessResponse = b
	if s.ProcessResponseChan != nil {
		s.ProcessResponseChan <- b
	}
})

var pluginCleanupRequestFn = makeWriteHandler(func(s *GeneratorStack) []byte {
	return s.GeneratorCleanupRequest
})

var pluginCleanupResponseFn = makeReadHandler(func(s *GeneratorStack, b []byte) {
	s.GeneratorCleanupResponse = b
	if s.CleanupResponseChan != nil {
		s.CleanupResponseChan <- b
	}
})

func getShutdownRequestedFn(ctx context.Context, mod api.Module, stack []uint64) {
	// Read the shutdown requested flag from the stack
	shutdownRequested := paramsFromContext(ctx).RequestedShutdown.Load()

	// Write the shutdown requested flag to the stack
	if shutdownRequested {
		stack[0] = 1
	} else {
		stack[0] = 0
	}
}

// moduleInstanceFor returns the module instance from the context that contains the internal
// state required for WASI host functions.
// NOTE: wasi-go returns context containing internal state when initializing the host module,
// and the same context is required when calling wasi functions exposed by wasi-go.
// This is a kind of workaround to avoid panic when calling
// wasi functions with different context than the one used to instantiate the host module.
func moduleInstanceFor[T wazergo.Module](ctx context.Context) (res T, ok bool) {
	res, ok = ctx.Value((*wazergo.ModuleInstance[T])(nil)).(T)
	return
}

// withModuleInstance returns a Go context inheriting from ctx and containing the
// state needed for module instantiated from wazero host module to properly bind
// their methods to their receiver (e.g. the module instance).
// NOTE: wasi-go returns context containing internal state when initializing the
// host module, and the same context is required when calling wasi functions
// exposed by wasi-go. This is a kind of workaround to avoid panic when calling
// wasi functions with different context than the one used to instantiate the host module.
func withModuleInstance[T wazergo.Module](ctx context.Context, instance T) context.Context {
	return context.WithValue(ctx, (*wazergo.ModuleInstance[T])(nil), instance)
}

func (p *wasmPlugin) CallInitWithGolang(ctx context.Context, config []byte) ([]byte, error) {
	if p.functions.init == nil {
		return nil, fmt.Errorf("plugin_init function not found")
	}

	resp := make(chan []byte, 1)
	res, err := p.ProcessFunctionCall(ctx, p.functions.init, &GeneratorStack{
		GeneratorInitRequest: config,
		InitResponseChan:     resp,
	}, 0, 0, 0, 0) // dummy args
	if err != nil {
		return nil, fmt.Errorf("plugin_init failed: %w", err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no return value")
	}
	// Respect caller-provided deadline if any, otherwise use a default timeout.
	if _, ok := ctx.Deadline(); ok {
		select {
		case out := <-resp:
			return out, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
		}
	}

	// No deadline on ctx: apply a default timeout (adjust as needed).
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case out := <-resp:
		return out, nil
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for plugin process")
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
	}
}

func (p *wasmPlugin) CallProcessWithGolang(ctx context.Context, input []byte) ([]byte, error) {
	if p.functions.process == nil {
		return nil, fmt.Errorf("plugin_process function not found")
	}

	// buffered so a late sender won't block if we time out
	resp := make(chan []byte, 1)
	res, err := p.ProcessFunctionCall(ctx, p.functions.process, &GeneratorStack{
		GeneratorProcessRequest: input,
		ProcessResponseChan:     resp,
	}, 0, 0, 0, 0) // dummy args
	if err != nil {
		return nil, fmt.Errorf("plugin_process failed: %w", err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no return value")
	}

	// Respect caller-provided deadline if any, otherwise use a default timeout.
	if _, ok := ctx.Deadline(); ok {
		select {
		case out := <-resp:
			return out, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
		}
	}

	// No deadline on ctx: apply a default timeout (adjust as needed).
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case out := <-resp:
		return out, nil
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for plugin process")
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
	}
}

func (p *wasmPlugin) CallCleanupWithGolang(ctx context.Context, input []byte) ([]byte, error) {
	if p.functions.cleanup == nil {
		return nil, fmt.Errorf("plugin_cleanup function not found")
	}

	resp := make(chan []byte, 1)
	res, err := p.ProcessFunctionCall(ctx, p.functions.cleanup, &GeneratorStack{
		GeneratorCleanupRequest: input,
		CleanupResponseChan:     resp,
	}, 0, 0, 0, 0) // dummy args
	if err != nil {
		return nil, fmt.Errorf("plugin_cleanup failed: %w", err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no return value")
	}
	// Respect caller-provided deadline if any, otherwise use a default timeout.
	if _, ok := ctx.Deadline(); ok {
		select {
		case out := <-resp:
			return out, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
		}
	}

	// No deadline on ctx: apply a default timeout (adjust as needed).
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case out := <-resp:
		return out, nil
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for plugin process")
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for plugin process canceled: %w", ctx.Err())
	}
}
