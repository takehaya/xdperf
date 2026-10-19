package plugin

import (
	"bytes"
	"strings"
	"testing"
)

func TestGeneratorResponseContract(t *testing.T) {
	valid := `{"template_type":"variable","variable_packet_template":{"pattern":"mixed","variants":[{"kind":"tcp_flow","weight":1,"tcp_flow":{"destination":"192.0.2.2:80","flows":[{"bytes":"9007199254740993"}]}}]}}`
	for name, b := range map[string]string{
		"wrong envelope":    strings.Replace(valid, `"template_type":"variable"`, `"template_type":"raw"`, 1),
		"mixed envelope":    strings.Replace(valid, `"template_type":`, `"raw_packet_template":[{"length":64}],"template_type":`, 1),
		"old API":           `{"template_type":"tcp_scenario","tcp_scenario":{}}`,
		"number":            strings.Replace(valid, `"9007199254740993"`, `9007199254740993`, 1),
		"duplicate":         strings.Replace(valid, `"bytes":`, `"bytes":"1","BYTES":`, 1),
		"unicode duplicate": strings.Replace(valid, `"bytes":`, `"byteſ":"1","bytes":`, 1),
		"unknown":           strings.Replace(valid, `"bytes":`, `"typo":1,"bytes":`, 1),
		"trailing":          valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeGeneratorResponse([]byte(b)); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
	b := append([]byte(valid), bytes.Repeat([]byte(" "), maxPluginOutputBytes-len(valid))...)
	r, err := decodeGeneratorResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.VariablePacketTemplate.Variants[0].TCPFlow.Flows[0].Bytes != "9007199254740993" {
		t.Fatal("lost precision")
	}
	if _, err := decodeGeneratorResponse(append(b, ' ')); err == nil {
		t.Fatal("accepted oversized response")
	}
	for _, field := range []string{"flows", "FLOWS", "flowſ"} {
		for _, count := range []int{65535, 65536} {
			b := []byte(`{"` + field + `":[` + strings.Repeat(`{},`, count-1) + `{}]}`)
			if err := checkGeneratorJSON(b); (err != nil) != (count > 65535) {
				t.Fatalf("%s %d: %v", field, count, err)
			}
		}
	}
	for _, b := range []string{`{"flows":[{]}`, `{"flows":[]`, strings.Repeat(`[`, 18) + strings.Repeat(`]`, 18)} {
		if err := checkGeneratorJSON([]byte(b)); err == nil {
			t.Fatal("accepted malformed container")
		}
	}
}

func TestLegacyGeneratorResponseCompatibility(t *testing.T) {
	for _, b := range []string{
		`{"template_type":"raw","raw_packet_template":[],"extra":true}`,
		`{"template_type":"raw","note":"tcp_flow","metadata":{"kind":"tcp_flow"}}`,
		`{"template_type":"raw","template_type":"raw"}`,
		`{"template_type":"variable","variable_packet_template":{"pattern":"mixed","variants":[]},"extension":{"version":1}}`,
	} {
		if _, err := decodeGeneratorResponse([]byte(b)); err != nil {
			t.Fatalf("legacy input rejected: %v", err)
		}
	}
}

func TestGeneratorResponseNesting(t *testing.T) {
	for _, depth := range []int{9999, 10000, 100000} {
		b := []byte(`{"template_type":"raw","metadata":` + strings.Repeat(`[`, depth) + `0` + strings.Repeat(`]`, depth) + `}`)
		_, err := decodeGeneratorResponse(b)
		// The root object adds one level to encoding/json's 10,000 limit.
		if (err != nil) != (depth >= 10000) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
}
