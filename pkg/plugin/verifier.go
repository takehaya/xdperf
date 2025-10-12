package plugin

import (
	"context"
	"encoding/json"
	"fmt"
)

type VerifierAdapter struct {
	name    string
	version string
	plugin  *wasmPlugin
}

func NewVerifierAdapter(name, version string, plugin *wasmPlugin) *VerifierAdapter {
	return &VerifierAdapter{
		name:    name,
		version: version,
		plugin:  plugin,
	}
}

func (v *VerifierAdapter) Name() string {
	return v.name
}

func (v *VerifierAdapter) Version() string {
	return v.version
}

func (v *VerifierAdapter) Initialize(ctx context.Context, config []byte) error {
	return v.plugin.CallInit(ctx, config)
}

func (v *VerifierAdapter) Cleanup(ctx context.Context) error {
	if v.plugin.functions.cleanup == nil {
		return nil
	}
	_, err := v.plugin.functions.cleanup.Call(ctx)
	return err
}

// VerifyPacket はパケットを検証する
func (v *VerifierAdapter) VerifyPacket(ctx context.Context, input *VerifierInput) (*VerifierOutput, error) {
	// 入力データのシリアライズ
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	// プラグインの呼び出し
	outputBytes, err := v.plugin.CallProcess(ctx, inputBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to call plugin: %w", err)
	}

	// 出力のパース
	var output VerifierOutput
	if err := json.Unmarshal(outputBytes, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output: %w", err)
	}

	return &output, nil
}

// GetStats は検証統計を返す
func (v *VerifierAdapter) GetStats(ctx context.Context) (*VerifierStats, error) {
	// stats_requestというコマンドを送る
	request := map[string]string{
		"command": "get_stats",
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// プラグインの呼び出し
	responseBytes, err := v.plugin.CallProcess(ctx, requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to call plugin: %w", err)
	}

	// レスポンスのパース
	var stats VerifierStats
	if err := json.Unmarshal(responseBytes, &stats); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats: %w", err)
	}

	return &stats, nil
}
