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

	return decodeGeneratorResponse(outputBytes, false)
}

func (g *GeneratorAdapter) Call(ctx context.Context, input []byte) ([]byte, error) {
	return g.plugin.CallProcess(ctx, input)
}

// GenerateTCPScenario uses the same exports as packet generators, but a separate
// request and strict response contract. Semantic validation belongs to xdperf.
func (g *GeneratorAdapter) GenerateTCPScenario(ctx context.Context, input guest.TCPScenarioRequest) (*guest.TCPScenario, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out, err := g.plugin.CallProcess(ctx, b)
	if err != nil {
		return nil, err
	}
	resp, err := decodeGeneratorResponse(out, true)
	if err != nil {
		return nil, err
	}
	return resp.TCPScenario, nil
}

func decodeGeneratorResponse(b []byte, tcp bool) (*guest.GeneratorProcessResponse, error) {
	if len(b) > maxPluginOutputBytes {
		return nil, fmt.Errorf("plugin response exceeds %d bytes", maxPluginOutputBytes)
	}
	var resp guest.GeneratorProcessResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	if tcp {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("invalid plugin response: %w", err)
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("trailing data in plugin response")
	}
	if tcp {
		if resp.TemplateType != guest.GeneratorTemplateTypeTCPScenario || resp.TCPScenario == nil {
			return nil, fmt.Errorf("--tcp plugin must return template_type tcp_scenario and its body")
		}
		// A string's zero value cannot distinguish omission from null or "".
		// Inspect presence at the wire boundary before semantic validation.
		var wire struct {
			TCPScenario struct {
				DurationNS json.RawMessage `json:"duration_ns"`
			} `json:"tcp_scenario"`
		}
		if err := json.Unmarshal(b, &wire); err != nil {
			return nil, fmt.Errorf("invalid plugin response: %w", err)
		}
		if wire.TCPScenario.DurationNS != nil && resp.TCPScenario.DurationNS == "" {
			return nil, fmt.Errorf("duration_ns must be a nonempty decimal string when specified")
		}
		if len(resp.RawPacketTemplate) != 0 || len(resp.VariablePacketTemplate.Variants) != 0 || resp.VariablePacketTemplate.Pattern != "" {
			return nil, fmt.Errorf("tcp_scenario cannot include raw or variable templates")
		}
	} else if resp.TemplateType == guest.GeneratorTemplateTypeTCPScenario || resp.TCPScenario != nil {
		return nil, fmt.Errorf("tcp_scenario requires --tcp")
	}
	return &resp, nil
}
