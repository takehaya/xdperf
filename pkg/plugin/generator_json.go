package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// A source port of zero is unavailable, even with the smallest port base.
const maxGeneratorEntries = 65535

// checkGeneratorJSON bounds allocations before decoding into SDK slices.
// The typed decoder still checks field names and types, and xdperf checks the
// actual port capacity. The valid schema is shallower than 16 levels and has
// fewer than 16 members per object; these guards bound malformed structures too.
func checkGeneratorJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkGeneratorJSON(dec, "", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data in plugin response")
	}
	return nil
}

func walkGeneratorJSON(dec *json.Decoder, field string, depth int) error {
	if depth > 16 {
		return fmt.Errorf("generator JSON exceeds nesting limit")
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
				return fmt.Errorf("generator JSON object exceeds member limit")
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
					return fmt.Errorf("duplicate generator JSON key %q", key)
				}
			}
			keys = append(keys, key)
			if err := walkGeneratorJSON(dec, key, depth+1); err != nil {
				return err
			}
		}
	case '[':
		limit := maxGeneratorEntries
		switch {
		case strings.EqualFold(field, "variants"), strings.EqualFold(field, "raw_packet_template"):
			limit = 16
		}
		for count := 0; dec.More(); count++ {
			if count == limit {
				return fmt.Errorf("generator array %q exceeds %d entries", field, limit)
			}
			if err := walkGeneratorJSON(dec, "", depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = dec.Token() // Decoder checks the matching closing delimiter.
	return err
}

// usesTCPVariants recognizes union keys even when escaped or case-folded.
// Unknown legacy metadata stays outside the union and remains permissive.
func usesTCPVariants(dec *json.Decoder, path string) (bool, error) {
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return false, err
	}
	if path == "kind" && token == "tcp_flow" {
		return true, nil
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	for dec.More() {
		child := ""
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return false, err
			}
			name, ok := key.(string)
			if !ok {
				return false, fmt.Errorf("expected JSON key")
			}
			switch {
			case path == "root" && strings.EqualFold(name, "variable_packet_template"):
				child = "set"
			case path == "set" && strings.EqualFold(name, "variants"):
				child = "variants"
			case path == "variant" && strings.EqualFold(name, "tcp_flow"):
				return true, nil
			case path == "variant" && strings.EqualFold(name, "kind"):
				child = "kind"
			}
		} else if delim == '[' && path == "variants" {
			child = "variant"
		}
		found, err := usesTCPVariants(dec, child)
		if err != nil || found {
			return found, err
		}
	}
	_, err = dec.Token()
	return false, err
}
