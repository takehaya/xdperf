package guest

import "encoding/json"

// TCPScenarioRequest describes the host's static TCP scenario capabilities.
// Config is kept separate from host-reserved fields and is plugin-specific JSON.
type TCPScenarioRequest struct {
	Mode              string            `json:"mode"`
	SupportedVersions []int             `json:"supported_versions"`
	Capabilities      []string          `json:"capabilities"`
	DeviceName        string            `json:"device_name"`
	Limits            TCPScenarioLimits `json:"limits"`
	Config            json.RawMessage   `json:"config"`
}

type TCPScenarioLimits struct {
	MaxSlots         int `json:"max_slots"`
	MaxEndpoints     int `json:"max_endpoints"`
	MaxResponseBytes int `json:"max_response_bytes"`
}

// TCPScenario is version 1 of the static, single-destination scenario.
// Uint64 values are decimal strings to preserve precision across JSON runtimes.
type TCPScenario struct {
	Version    int                   `json:"version"`
	Requires   []string              `json:"requires"`
	ScenarioID string                `json:"scenario_id"`
	Seed       string                `json:"seed"`
	MaxActive  int                   `json:"max_active"`
	DurationNS string                `json:"duration_ns,omitempty"`
	Endpoints  []TCPScenarioEndpoint `json:"endpoints"`
	Payloads   []TCPScenarioPayload  `json:"payloads"`
	Flows      []TCPScenarioFlow     `json:"flows"`
}

type TCPScenarioEndpoint struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type TCPScenarioPayload struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type TCPScenarioFlow struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Bytes    string `json:"bytes"`
	Payload  string `json:"payload"`
	StartNS  string `json:"start_ns"`
}
