package xdperf

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseCount parses a count string with optional suffix (k, m).
// Examples: "100k" -> 100000, "1m" -> 1000000, "50000" -> 50000
// Returns 0 if empty string.
func ParseCount(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}

	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}

	var multiplier uint64 = 1
	if strings.HasSuffix(s, "k") {
		multiplier = 1000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		multiplier = 1000000
		s = s[:len(s)-1]
	}

	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value: %s", s)
	}

	return value * multiplier, nil
}

// ParsePPS parses a PPS string with optional suffix (k, m).
// Examples: "100k" -> 100000, "1m" -> 1000000, "50000" -> 50000
// Returns 0 if empty string (meaning unlimited/max speed)
func ParsePPS(s string) (uint64, error) {
	result, err := ParseCount(s)
	if err != nil {
		return 0, fmt.Errorf("invalid PPS value: %w", err)
	}
	return result, nil
}
