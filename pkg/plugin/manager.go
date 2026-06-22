package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/stealthrocket/wasi-go"
	"github.com/stealthrocket/wasi-go/imports"
	"github.com/stealthrocket/wasi-go/imports/wasi_snapshot_preview1"
	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"
)

// ManagerOption is a functional option for NewManager
type ManagerOption func(*managerOptions)

type managerOptions struct {
	cacheDir string
	logger   *zap.Logger
}

// WithCacheDir sets the directory for WASM compilation cache
func WithCacheDir(dir string) ManagerOption {
	return func(o *managerOptions) {
		o.cacheDir = dir
	}
}

// WithLogger sets the structured logger used to surface plugin host calls
// (host_log / host_report_metric) instead of writing them to stdout.
func WithLogger(lg *zap.Logger) ManagerOption {
	return func(o *managerOptions) {
		o.logger = lg
	}
}

// Manager is the plugin manager
type Manager struct {
	runtime          wazero.Runtime
	cache            wazero.CompilationCache
	plugins          map[string]*wasmPlugin
	pluginDir        string
	mu               sync.RWMutex
	wasiP1HostModule *wasi_snapshot_preview1.Module
	wasiSys          *wasi.System
	pluginLang       string
	logger           *zap.Logger

	pluginCfg string
}

// wasmPlugin is a wrapper for WASM plugins
type wasmPlugin struct {
	metadata  PluginMetadata
	module    api.Module
	memory    api.Memory
	functions struct {
		init    api.Function
		process api.Function
		cleanup api.Function
		malloc  api.Function
		free    api.Function
	}
	wasiP1HostModule *wasi_snapshot_preview1.Module
	pluginLang       string
}

// NewManager is a function to create a new plugin manager
func NewManager(pluginDir string, pluginCfg string, pluginLang string, opts ...ManagerOption) (*Manager, error) {
	ctx := context.Background()

	options := &managerOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Resolve cache directory
	cacheDir := options.cacheDir
	if cacheDir == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			userCache = os.TempDir()
		}
		cacheDir = filepath.Join(userCache, "xdperf", "wasm")
	}

	// Create file-backed compilation cache (falls back to in-memory on error)
	cache, err := wazero.NewCompilationCacheWithDir(cacheDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to create WASM disk cache at %s: %v (using in-memory cache)\n", cacheDir, err)
		cache = wazero.NewCompilationCache()
	}

	runtimeConfig := wazero.NewRuntimeConfig().WithCompilationCache(cache)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)

	ctx, sys, err := imports.NewBuilder().
		WithEnv(os.Environ()...).Instantiate(ctx, runtime)
	if err != nil {
		return nil, fmt.Errorf("wasm: error instantiating wasi module: %w", err)
	}
	wasiP1HostModule, ok := moduleInstanceFor[*wasi_snapshot_preview1.Module](ctx)
	if !ok {
		return nil, fmt.Errorf("wasm: error retrieving wasi host module instance")
	}

	lg := options.logger
	if lg == nil {
		lg = zap.NewNop()
	}
	m := &Manager{
		runtime:          runtime,
		cache:            cache,
		plugins:          make(map[string]*wasmPlugin),
		pluginDir:        pluginDir,
		wasiP1HostModule: wasiP1HostModule,
		wasiSys:          &sys,
		pluginLang:       pluginLang,
		logger:           lg,
		pluginCfg:        pluginCfg,
	}
	if err := m.registerHostAPIFunctions(ctx); err != nil {
		return nil, fmt.Errorf("failed to register host functions: %w", err)
	}
	if pluginLang == "go" {
		_, err := instantiateHostModule(ctx, runtime)
		if err != nil {
			return nil, fmt.Errorf("wasm: error instantiating host module: %w", err)
		}
	}

	return m, nil
}

// registerHostFunctions はホスト関数を登録する
func (m *Manager) registerHostAPIFunctions(ctx context.Context) error {
	hostModule := m.runtime.NewHostModuleBuilder("env")

	hostModule.NewFunctionBuilder().WithFunc(makeLogFunc(m.logger)).Export("host_log")
	hostModule.NewFunctionBuilder().WithFunc(makeMetricFunc(m.logger)).Export("host_report_metric")
	hostModule.NewFunctionBuilder().WithFunc(neighborResolveFunc).Export("host_neighbor_resolve")

	_, err := hostModule.Instantiate(ctx)
	return err
}

// LoadPlugin はプラグインをロードする
func (m *Manager) LoadPlugin(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already loaded", name)
	}

	pluginPath := filepath.Join(m.pluginDir, name+".wasm")
	wasmBytes, err := os.ReadFile(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin file: %w", err)
	}

	// TODO: メタデータの読み込み
	metadataPath := filepath.Join(m.pluginDir, name+".json")
	metadata := PluginMetadata{
		Name:    name,
		Version: "unknown",
	}
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
		// TODO: JSONパース
		_ = metadataBytes
	}
	ctx = withModuleInstance(ctx, m.wasiP1HostModule)

	// Compile module (uses disk cache on subsequent runs)
	compileStart := time.Now()
	compiled, err := m.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("failed to compile plugin module %s: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "wasm: compiled %s (%d bytes) in %v\n", name, len(wasmBytes), time.Since(compileStart))

	// Instantiate from pre-compiled module
	module, err := m.runtime.InstantiateModule(ctx, compiled,
		wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return fmt.Errorf("failed to instantiate module: %w", err)
	}

	plugin := &wasmPlugin{
		metadata:         metadata,
		module:           module,
		memory:           module.Memory(),
		wasiP1HostModule: m.wasiP1HostModule,
		pluginLang:       m.pluginLang,
	}

	// エクスポート関数の取得
	plugin.functions.init = module.ExportedFunction("plugin_init")
	plugin.functions.process = module.ExportedFunction("plugin_process")
	plugin.functions.cleanup = module.ExportedFunction("plugin_cleanup")
	plugin.functions.malloc = module.ExportedFunction("malloc")
	plugin.functions.free = module.ExportedFunction("free")

	// malloc/freeのチェック
	if plugin.functions.malloc == nil || plugin.functions.free == nil {
		return fmt.Errorf("plugin missing memory management functions (malloc, free)")
	}

	// 必須関数のチェック
	if plugin.functions.init == nil || plugin.functions.process == nil {
		return fmt.Errorf("plugin missing required functions (plugin_init, plugin_process)")
	}

	m.plugins[name] = plugin
	return nil
}

// UnloadPlugin はプラグインをアンロードする
func (m *Manager) UnloadPlugin(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not loaded", name)
	}
	cleanupReq := guest.GeneratorInitRequest{
		PluginConfig: []byte(m.pluginCfg),
	}
	cleanupReqJSON, err := json.Marshal(cleanupReq)
	if err != nil {
		return fmt.Errorf("failed to marshal cleanup request: %w", err)
	}
	if _, err := plugin.CallCleanup(ctx, cleanupReqJSON); err != nil {
		return fmt.Errorf("failed to cleanup plugin %s: %w", name, err)
	}

	if err := plugin.module.Close(ctx); err != nil {
		return fmt.Errorf("failed to close module: %w", err)
	}

	delete(m.plugins, name)
	return nil
}

// GetPlugin はロード済みプラグインを取得する
func (m *Manager) GetPlugin(name string) (*wasmPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not loaded", name)
	}

	return plugin, nil
}

// Close is the cleanup function for Manager
func (m *Manager) Close(ctx context.Context) error {
	m.mu.RLock()
	names := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		names = append(names, name)
	}
	m.mu.RUnlock()

	var firstErr error
	for _, name := range names {
		if err := m.UnloadPlugin(ctx, name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.runtime.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if m.cache != nil {
		if err := m.cache.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ProcessFunctionCall executes a WASM function and handles stack management
func (p *wasmPlugin) ProcessFunctionCall(ctx context.Context, fn api.Function, stack *GeneratorStack, args ...uint64) ([]uint64, error) {
	ctx = createContextWithStack(ctx, stack)
	// Set the WASI host module instance in the context
	ctx = withModuleInstance(ctx, p.wasiP1HostModule)
	return fn.Call(ctx, args...)
}

// CallPluginInit is a function to call plugin_init
func (p *wasmPlugin) CallInit(ctx context.Context, config []byte) ([]byte, error) {
	if p.functions.init == nil {
		return nil, fmt.Errorf("plugin_init function not found")
	}
	if p.pluginLang == "go" {
		return p.CallInitWithGolang(ctx, config)
	}

	return p.callReadAndResp(ctx, config, p.functions.init)
}

// CallPluginProcess is a function to call plugin_process
func (p *wasmPlugin) CallProcess(ctx context.Context, input []byte) ([]byte, error) {
	if p.functions.process == nil {
		return nil, fmt.Errorf("plugin_process function not found")
	}
	if p.pluginLang == "go" {
		return p.CallProcessWithGolang(ctx, input)
	}

	return p.callReadAndResp(ctx, input, p.functions.process)
}

// CallPluginCleanup is a function to call plugin_cleanup
func (p *wasmPlugin) CallCleanup(ctx context.Context, input []byte) ([]byte, error) {
	if p.functions.cleanup == nil {
		return nil, fmt.Errorf("plugin_cleanup function not found")
	}
	if p.pluginLang == "go" {
		return p.CallCleanupWithGolang(ctx, input)
	}

	return p.callReadAndResp(ctx, input, p.functions.cleanup)
}
func (p *wasmPlugin) callReadAndResp(ctx context.Context, input []byte, caller api.Function) ([]byte, error) {
	ctx = withModuleInstance(ctx, p.wasiP1HostModule)
	if len(input) == 0 {
		input = []byte{}
	}

	inPtr, err := p.writeToMemory(ctx, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		// free input memory; a failure here must not crash the host process
		// (a misbehaving plugin's free could trap), so log and continue.
		if _, err := p.functions.free.Call(ctx, uint64(inPtr)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to free plugin input memory: %v\n", err)
		}
	}()

	// allocate memory for output
	cap := uint32(1024 * 1024 * 32) // 32MB
	res, err := p.functions.malloc.Call(ctx, uint64(cap))
	if err != nil || len(res) == 0 {
		return nil, fmt.Errorf("malloc for output failed: %w", err)
	}
	outPtr := uint32(res[0])
	defer func() {
		// free output memory; log-and-continue rather than panic (see above).
		if _, err := p.functions.free.Call(ctx, uint64(outPtr)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to free plugin output memory: %v\n", err)
		}
	}()

	// call plugin function
	r, err := caller.Call(ctx, uint64(inPtr), uint64(len(input)), uint64(outPtr), uint64(cap))
	if err != nil {
		return nil, fmt.Errorf("plugin function call failed: %w", err)
	}
	if len(r) == 0 {
		return nil, fmt.Errorf("no return value")
	}

	outLen := uint32(r[0])
	if outLen > cap {
		return nil, fmt.Errorf("output size exceeds capacity")
	}

	buf, ok := p.memory.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("read output failed")
	}

	return append([]byte(nil), buf...), nil
}

func (p *wasmPlugin) writeToMemory(ctx context.Context, data []byte) (uint32, error) {
	res, err := p.functions.malloc.Call(ctx, uint64(len(data)))
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("alloc failed")
	}
	ptr := uint32(res[0])
	if !p.memory.Write(ptr, data) {
		return 0, fmt.Errorf("write failed")
	}
	return ptr, nil
}
