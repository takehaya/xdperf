package main

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/takehaya/xdperf/pkg/guest"
	"github.com/takehaya/xdperf/pkg/guest/goshim"
)

func main() {}

//go:wasmexport plugin_init
func plugin_init(_, _, _, _ uint32) int32 {
	_ = goshim.PluginGeneratorInitRequest()
	goshim.PluginGeneratorInitResponse(guest.GeneratorInitResponse{Success: true})
	return 1
}

//go:wasmexport plugin_process
func plugin_process(_, _, _, _ uint32) int32 {
	req := goshim.PluginGeneratorProcessRequest[guest.TCPScenarioRequest]()
	if req.Mode != "tcp_scenario" || !slices.Contains(req.SupportedVersions, 1) ||
		!slices.Contains(req.Capabilities, "static_flows") || !slices.Contains(req.Capabilities, "zero_payload") ||
		req.Limits.MaxSlots < 4 || req.Limits.MaxEndpoints < 1 {
		panic("heavyhitter requires TCP scenario version 1 with four static flows and zero payload")
	}
	cfg := struct {
		Address    string `json:"address"`
		Port       int    `json:"port"`
		Seed       string `json:"seed"`
		SmallBytes string `json:"small_bytes"`
		LargeBytes string `json:"large_bytes"`
	}{"192.168.110.2", 5201, "42", "65536", "67108864"}
	b, err := json.Marshal(req.Config)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		panic(err)
	}
	s := &guest.TCPScenario{
		Version: 1, Requires: []string{"static_flows", "zero_payload"},
		ScenarioID: "heavy-hitter-4", Seed: cfg.Seed, MaxActive: 4,
		Endpoints: []guest.TCPScenarioEndpoint{{ID: "sink", Address: cfg.Address, Port: cfg.Port}},
		Payloads:  []guest.TCPScenarioPayload{{ID: "zero", Kind: "zero"}},
	}
	for i := 0; i < 4; i++ {
		n := cfg.SmallBytes
		if i == 3 {
			n = cfg.LargeBytes
		}
		s.Flows = append(s.Flows, guest.TCPScenarioFlow{ID: fmt.Sprintf("f%d", i), Endpoint: "sink", Bytes: n, Payload: "zero", StartNS: "0"})
	}
	goshim.PluginGeneratorProcessResponse(guest.GeneratorProcessResponse{TemplateType: guest.GeneratorTemplateTypeTCPScenario, TCPScenario: s})
	return 1
}

//go:wasmexport plugin_cleanup
func plugin_cleanup(_, _, _, _ uint32) int32 {
	_ = goshim.PluginGeneratorCleanupRequest()
	guest.Log(1, "heavyhitter cleanup")
	goshim.PluginGeneratorCleanupResponse(guest.GeneratorCleanupResponse{Success: true})
	return 0
}
