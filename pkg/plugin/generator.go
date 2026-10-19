package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

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

	return decodeGeneratorResponse(outputBytes)
}

func (g *GeneratorAdapter) Call(ctx context.Context, input []byte) ([]byte, error) {
	return g.plugin.CallProcess(ctx, input)
}

func decodeGeneratorResponse(b []byte) (*guest.GeneratorProcessResponse, error) {
	if len(b) > maxPluginOutputBytes {
		return nil, fmt.Errorf("plugin response exceeds %d bytes", maxPluginOutputBytes)
	}
	// Bound recursion in the union probe by encoding/json's syntax/depth
	// limit before walking arbitrary legacy metadata.
	if !json.Valid(b) {
		return nil, fmt.Errorf("invalid plugin response JSON")
	}
	// Inspect only the variant union, without allocating flow or variant slices.
	strict, err := usesTCPVariants(json.NewDecoder(bytes.NewReader(b)), "root")
	if err != nil {
		return nil, fmt.Errorf("invalid plugin response: %w", err)
	}
	if strict {
		if err := checkGeneratorJSON(b); err != nil {
			return nil, err
		}
	}
	var envelope struct {
		Removed json.RawMessage `json:"tcp_scenario"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return nil, err
	}
	if envelope.Removed != nil {
		return nil, fmt.Errorf("tcp_scenario was replaced by TCP flow variants")
	}
	var resp guest.GeneratorProcessResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("invalid plugin response: %w", err)
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("trailing data in plugin response")
	}
	if resp.TemplateType != guest.GeneratorTemplateTypeRaw && resp.TemplateType != guest.GeneratorTemplateTypeVariable {
		return nil, fmt.Errorf("unknown template type %q", resp.TemplateType)
	}
	if strict && (resp.TemplateType != guest.GeneratorTemplateTypeVariable || len(resp.RawPacketTemplate) != 0) {
		return nil, fmt.Errorf("TCP flow variants require an unmixed variable template envelope")
	}
	return &resp, nil
}
