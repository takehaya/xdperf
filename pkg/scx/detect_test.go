package scx

import "testing"

func TestSupportedVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		info    Info
		wantErr bool
	}{
		{"not_available", Info{}, true},
		{"available_but_6_12", Info{Available: true}, true},
		{"usable", Info{Available: true, KfuncOK: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := supported(tt.info); (err != nil) != tt.wantErr {
				t.Errorf("supported(%+v) error = %v, wantErr %v", tt.info, err, tt.wantErr)
			}
		})
	}
}

func TestDetectDoesNotPanic(t *testing.T) {
	info := Detect()
	// On kernels without CONFIG_SCHED_EXT everything must stay zero-valued.
	if !info.Available && (info.State != "" || info.RootOps != "" || info.KfuncOK) {
		t.Errorf("unavailable sched_ext must not report details: %+v", info)
	}
}
