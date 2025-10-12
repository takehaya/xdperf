package xdperf

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/takehaya/xdperf/pkg/plugin"
	"go.uber.org/zap"
)

type CancelFunc func(ctx context.Context) error
type Xdperf struct {
	Logger        *zap.Logger
	PluginManager *plugin.Manager
	cleanupFnList []CancelFunc

	cfg Config
}

type Config struct {
	LoggerConfig logger.Config

	// From For CLI Flags
	PluginPath   string
	PluginName   string
	PluginConfig string
	ServerFlag   bool
}

func NewXdperf(cfg Config) (*Xdperf, error) {
	var cleanupFnList []CancelFunc
	logger, cleanup, err := logger.NewLogger(cfg.LoggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed init logger: %w", err)
	}
	cleanupFnList = append(cleanupFnList, cleanup)

	pm, err := plugin.NewManager(cfg.PluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed init plugin manager: %w", err)
	}

	if err = pm.LoadPlugin(context.Background(), cfg.PluginName); err != nil {
		return nil, fmt.Errorf("failed load plugin: %w", err)
	}
	cleanupFnList = append(cleanupFnList, pm.Close)

	return &Xdperf{
		Logger:        logger,
		PluginManager: pm,
		cleanupFnList: cleanupFnList,
		cfg:           cfg,
	}, nil
}

func (x *Xdperf) StartClient(ctx context.Context) error {
	x.Logger.Info("start client mode")

	return x.startClientSimple(ctx)
}

// startClientSimple はシンプルなプラグインテスト
func (x *Xdperf) startClientSimple(ctx context.Context) error {
	wasmPlugin, err := x.PluginManager.GetPlugin(x.cfg.PluginName)
	if err != nil {
		return fmt.Errorf("failed get plugin: %w", err)
	}

	generator := plugin.NewGeneratorAdapter(x.cfg.PluginName, wasmPlugin)
	x.Logger.Info("testing simple plugin communication")

	// 3回テスト呼び出し
	for seq := uint64(0); seq < 3; seq++ {
		// シンプルな入力
		input := map[string]interface{}{
			"sequence": seq,
		}

		x.Logger.Info("calling plugin", zap.Uint64("sequence", seq))

		// プラグイン呼び出し
		outputBytes, err := generator.CallWithJSON(ctx, input)
		if err != nil {
			x.Logger.Error("CallWithJSON failed", zap.Error(err))
			return fmt.Errorf("failed to call plugin (seq=%d): %w", seq, err)
		}
		x.Logger.Info("after CallWithJSON success")

		x.Logger.Info("received response",
			zap.Uint64("sequence", seq),
			zap.Int("output_size", len(outputBytes)),
			zap.String("output", string(outputBytes)),
		)

		// JSONパース
		var response map[string]interface{}
		if err := json.Unmarshal(outputBytes, &response); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		x.Logger.Info("parsed response",
			zap.Any("message", response["message"]),
			zap.Any("status", response["status"]),
		)
	}

	x.Logger.Info("plugin test completed successfully")
	return nil
}

// func (x *Xdperf) loadConfigFile(path string) ([]byte, error) {
// 	data, err := os.ReadFile(path)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read config file: %w", err)
// 	}

// 	ext := filepath.Ext(path)
// 	switch ext {
// 	case ".json":
// 		// JSONはそのまま返す
// 		return data, nil
// 	case ".yaml", ".yml":
// 		// YAMLをJSONに変換
// 		var yamlData interface{}
// 		if err := yaml.Unmarshal(data, &yamlData); err != nil {
// 			return nil, fmt.Errorf("failed to parse YAML: %w", err)
// 		}
// 		jsonData, err := json.Marshal(yamlData)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
// 		}
// 		return jsonData, nil
// 	default:
// 		return nil, fmt.Errorf("unsupported config file extension: %s (supported: .json, .yaml, .yml)", ext)
// 	}
// }

func (x *Xdperf) Close() {
	for _, fn := range x.cleanupFnList {
		if err := fn(context.Background()); err != nil {
			x.Logger.Error("failed to cleanup", zap.Error(err))
		}
	}
	x.Logger.Info("xdperf cleanup completed")
}
