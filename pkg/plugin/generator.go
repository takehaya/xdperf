package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/takehaya/xdperf/pkg/guest"
)

// GeneratorAdapter wraps a loaded wasmPlugin and adapts its raw call interface
// to the host-side generator API (guest.GeneratorProcessResponse).
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

func (g *GeneratorAdapter) Initialize(ctx context.Context, config []byte) ([]byte, error) {
	return g.plugin.CallInit(ctx, config)
}

func (g *GeneratorAdapter) Cleanup(ctx context.Context) ([]byte, error) {
	return g.plugin.CallCleanup(ctx, nil)
}

func (g *GeneratorAdapter) GenerateTemplate(ctx context.Context, input map[string]interface{}) (*guest.GeneratorProcessResponse, error) {
	// input data serialization
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	outputBytes, err := g.plugin.CallProcess(ctx, inputBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to call plugin: %w", err)
	}

	var output guest.GeneratorProcessResponse
	if err := json.Unmarshal(outputBytes, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output: %w", err)
	}

	return &output, nil
}

func (g *GeneratorAdapter) Call(ctx context.Context, input []byte) ([]byte, error) {
	return g.plugin.CallProcess(ctx, input)
}
