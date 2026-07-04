package telemetry

import (
	"context"
	"reflect"
	"testing"

	"go.uber.org/zap"
)

func TestParseAttributes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "single pair", input: "site=lab1", want: map[string]string{"site": "lab1"}},
		{
			name:  "multiple pairs",
			input: "test.run.id=abc,site=lab1",
			want:  map[string]string{"test.run.id": "abc", "site": "lab1"},
		},
		{
			name:  "spaces trimmed",
			input: " site = lab1 , env = dev ",
			want:  map[string]string{"site": "lab1", "env": "dev"},
		},
		{name: "empty value allowed", input: "site=", want: map[string]string{"site": ""}},
		{name: "trailing comma ignored", input: "site=lab1,", want: map[string]string{"site": "lab1"}},
		{name: "missing equals", input: "site", wantErr: true},
		{name: "empty key", input: "=lab1", wantErr: true},
		{name: "bad pair among good ones", input: "site=lab1,oops", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAttributes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAttributes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseAttributes(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewResource(t *testing.T) {
	res, err := newResource(context.Background(), Config{
		Mode:       "client",
		Device:     "eth0",
		Version:    "1.2.3",
		Attributes: map[string]string{"site": "lab1"},
	})
	if err != nil {
		t.Fatalf("newResource() error = %v", err)
	}

	got := make(map[string]string)
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.String()
	}
	want := map[string]string{
		"service.name":           "xdperf",
		"service.version":        "1.2.3",
		"xdperf.mode":            "client",
		"network.interface.name": "eth0",
		"site":                   "lab1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("resource attribute %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestZapErrorHandlerSuppressesRepeats(t *testing.T) {
	// Smoke test: repeated identical errors must not panic and must keep
	// tracking the last message across calls.
	h := &zapErrorHandler{log: zap.NewNop()}
	err := context.DeadlineExceeded
	h.Handle(err)
	h.Handle(err)
	h.Handle(nil)
	if h.last != err.Error() {
		t.Errorf("last = %q, want %q", h.last, err.Error())
	}
}
