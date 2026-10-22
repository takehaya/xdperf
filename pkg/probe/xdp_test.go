package probe

import (
	"os"
	"testing"
)

func TestLegacyLiveFrameMode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires BPF privileges")
	}
	supported, err := probeLegacyLiveFrameMode()
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Skip("kernel live-frames API unavailable")
	}
}
