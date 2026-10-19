package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// A source port of zero is unavailable, even with the smallest port base.
const maxTCPScenarioEntries = 65535

// checkTCPScenarioJSON bounds allocations before decoding into SDK slices.
// The typed decoder still checks field names and types, and xdperf checks the
// actual port capacity. The valid schema is shallower than 16 levels and has
// fewer than 16 members per object; these guards bound malformed structures too.
func checkTCPScenarioJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkTCPScenarioJSON(dec, "", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data in plugin response")
	}
	return nil
}

func walkTCPScenarioJSON(dec *json.Decoder, field string, depth int) error {
	if depth > 16 {
		return fmt.Errorf("TCP scenario JSON exceeds nesting limit")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delim {
	case '{':
		var keys []string
		for dec.More() {
			if len(keys) == 16 {
				return fmt.Errorf("TCP scenario JSON object exceeds member limit")
			}
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("expected a JSON object key")
			}
			for _, previous := range keys {
				// Match encoding/json's case folding, including Unicode aliases.
				if strings.EqualFold(previous, key) {
					return fmt.Errorf("duplicate TCP scenario JSON key %q", key)
				}
			}
			keys = append(keys, key)
			if err := walkTCPScenarioJSON(dec, key, depth+1); err != nil {
				return err
			}
		}
	case '[':
		limit := maxTCPScenarioEntries
		switch {
		case strings.EqualFold(field, "endpoints"), strings.EqualFold(field, "payloads"):
			limit = 1
		case strings.EqualFold(field, "raw_packet_template"), strings.EqualFold(field, "variants"):
			limit = 0
		}
		for count := 0; dec.More(); count++ {
			if count == limit {
				return fmt.Errorf("TCP scenario array %q exceeds %d entries", field, limit)
			}
			if err := walkTCPScenarioJSON(dec, "", depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = dec.Token() // Decoder checks the matching closing delimiter.
	return err
}
