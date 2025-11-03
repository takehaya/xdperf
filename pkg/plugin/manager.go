package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Manager is the plugin manager
type Manager struct {
	runtime   wazero.Runtime
	plugins   map[string]*wasmPlugin
	pluginDir string
	mu        sync.RWMutex
	hostFuncs *hostFunctions
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
}

// hostFunctions is a collection of host functions
type hostFunctions struct {
	logFunc    func(level uint32, msg string)
	metricFunc func(name string, value float64, timestamp int64)
}

// NewManager is a function to create a new plugin manager
func NewManager(pluginDir string) (*Manager, error) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	_, err := wasi_snapshot_preview1.Instantiate(ctx, runtime)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate WASI: %w", err)
	}

	m := &Manager{
		runtime:   runtime,
		plugins:   make(map[string]*wasmPlugin),
		pluginDir: pluginDir,
		hostFuncs: &hostFunctions{
			logFunc: func(level uint32, msg string) {
				fmt.Printf("[PLUGIN] [%d] %s\n", level, msg)
			},
			metricFunc: func(name string, value float64, timestamp int64) {
				t := parseTimestamp(uint64(timestamp))
				fmt.Printf("[METRIC] %s %.6f time=%s \n",
					name,
					value,
					t.Format(time.RFC3339Nano),
				)
			},
		},
	}
	if err := m.registerHostFunctions(ctx); err != nil {
		return nil, fmt.Errorf("failed to register host functions: %w", err)
	}

	return m, nil
}

func parseTimestamp(ts uint64) time.Time {
	nowNs := time.Now().UnixNano()
	switch {
	case ts > uint64(nowNs/100): // ns order
		return time.Unix(0, int64(ts))
	case ts > uint64(nowNs/100_000): // us order
		return time.Unix(0, int64(ts*1000))
	case ts > uint64(nowNs/100_000_000): // ms order
		return time.Unix(0, int64(ts*1_000_000))
	default: // sec order
		return time.Unix(int64(ts), 0)
	}
}

// registerHostFunctions はホスト関数を登録する
func (m *Manager) registerHostFunctions(ctx context.Context) error {
	hostModule := m.runtime.NewHostModuleBuilder("env")

	// host_log関数の登録
	hostModule.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, level uint32, msgPtr, msgLen uint32) {
			data, ok := mod.Memory().Read(msgPtr, msgLen)
			if !ok {
				return
			}
			m.hostFuncs.logFunc(level, string(data))
		}).
		Export("host_log")

	// host_report_metric関数の登録
	hostModule.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, namePtr, nameLen uint32, value float64, timestamp int64) {
			data, ok := mod.Memory().Read(namePtr, nameLen)
			if !ok {
				return
			}
			m.hostFuncs.metricFunc(string(data), value, timestamp)
		}).
		Export("host_report_metric")

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

	metadataPath := filepath.Join(m.pluginDir, name+".json")
	metadata := PluginMetadata{
		Name:    name,
		Version: "unknown",
	}
	if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
		// TODO: JSONパース
		_ = metadataBytes
	}

	// WASMモジュールのコンパイルとインスタンス化
	// デフォルト設定で初期化（_startは呼ばれるがselectでブロックする）
	module, err := m.runtime.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().WithStartFunctions("_initialize"))
	if err != nil {
		return fmt.Errorf("failed to instantiate module: %w", err)
	}

	plugin := &wasmPlugin{
		metadata: metadata,
		module:   module,
		memory:   module.Memory(),
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

	if plugin.functions.cleanup != nil {
		_, err := plugin.functions.cleanup.Call(ctx)
		if err != nil {
			return fmt.Errorf("plugin cleanup failed: %w", err)
		}
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

// CallPlugin is a function to call a plugin's process function
func (m *Manager) CallPlugin(ctx context.Context, name string, input []byte) ([]byte, error) {
	plugin, err := m.GetPlugin(name)
	if err != nil {
		return nil, err
	}
	return plugin.CallProcess(ctx, input)
}

// InitPlugin はプラグインを初期化する
func (m *Manager) InitPlugin(ctx context.Context, name string, config []byte) error {
	plugin, err := m.GetPlugin(name)
	if err != nil {
		return err
	}
	return plugin.CallInit(ctx, config)
}

// ListPlugins is the list of loaded plugins
func (m *Manager) ListPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		names = append(names, name)
	}
	return names
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
	return firstErr
}

// CallPluginInit is a function to call plugin_init
func (p *wasmPlugin) CallInit(ctx context.Context, config []byte) error {
	if p.functions.init == nil {
		return fmt.Errorf("plugin_init function not found")
	}

	// configをメモリに書き込む
	configPtr, err := p.writeToMemory(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to write config to memory: %w", err)
	}

	// plugin_init(config_ptr, config_len) を呼び出す
	results, err := p.functions.init.Call(ctx, uint64(configPtr), uint64(len(config)))
	if err != nil {
		return fmt.Errorf("plugin_init failed: %w", err)
	}

	if len(results) > 0 && results[0] != 0 {
		return fmt.Errorf("plugin_init returned error code: %d", results[0])
	}

	return nil
}

// CallPluginProcess is a function to call plugin_process
func (p *wasmPlugin) CallProcess(ctx context.Context, input []byte) ([]byte, error) {
	if p.functions.process == nil {
		return nil, fmt.Errorf("plugin_process function not found")
	}

	// 入力データをメモリに書き込む
	inPtr, err := p.writeToMemory(ctx, input)
	if err != nil {
		return nil, err
	}

	// 出力用に十分なサイズを確保
	cap := uint32(1024 * 1024)
	res, err := p.functions.malloc.Call(ctx, uint64(cap))
	if err != nil || len(res) == 0 {
		return nil, fmt.Errorf("alloc out failed")
	}
	outPtr := uint32(res[0])

	r, err := p.functions.process.Call(ctx, uint64(inPtr), uint64(len(input)), uint64(outPtr), uint64(cap))
	if err != nil {
		return nil, fmt.Errorf("plugin_process failed: %w", err)
	}
	if len(r) == 0 {
		return nil, fmt.Errorf("no return value")
	}

	outLen := uint32(r[0])
	buf, ok := p.memory.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("read output failed")
	}

	// 後片付け
	if _, err = p.functions.free.Call(ctx, uint64(inPtr)); err != nil {
		return nil, fmt.Errorf("free input failed: %w", err)
	}
	if _, err = p.functions.free.Call(ctx, uint64(outPtr)); err != nil {
		return nil, fmt.Errorf("free output failed: %w", err)
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
