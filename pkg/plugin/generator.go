package plugin

import (
	"context"
	"encoding/json"
	"fmt"
)

// GeneratorAdapter はGeneratorPluginのアダプター
type GeneratorAdapter struct {
	name   string
	plugin *wasmPlugin
}

func NewGeneratorAdapter(name string, plugin *wasmPlugin) *GeneratorAdapter {
	return &GeneratorAdapter{
		name:   name,
		plugin: plugin,
	}
}

func (g *GeneratorAdapter) Name() string {
	return g.name
}

func (g *GeneratorAdapter) Initialize(ctx context.Context, config []byte) error {
	return g.plugin.CallInit(ctx, config)
}

func (g *GeneratorAdapter) Cleanup(ctx context.Context) error {
	if g.plugin.functions.cleanup == nil {
		return nil
	}
	_, err := g.plugin.functions.cleanup.Call(ctx)
	return err
}

func (g *GeneratorAdapter) GenerateTemplate(ctx context.Context, seq uint64, args []byte) (*GeneratorOutput, error) {
	// input data serialization
	input := map[string]interface{}{
		"sequence": seq,
		"args":     args,
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	outputBytes, err := g.plugin.CallProcess(ctx, inputBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to call plugin: %w", err)
	}

	var output GeneratorOutput
	if err := json.Unmarshal(outputBytes, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output: %w", err)
	}

	return &output, nil
}

func (g *GeneratorAdapter) Call(ctx context.Context, input []byte) ([]byte, error) {
	return g.plugin.CallProcess(ctx, input)
}

func (g *GeneratorAdapter) CallWithJSON(ctx context.Context, input interface{}) ([]byte, error) {
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}
	return g.plugin.CallProcess(ctx, inputBytes)
}
