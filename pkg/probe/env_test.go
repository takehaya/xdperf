package probe

import (
	"reflect"
	"testing"
)

func TestCmdlineParam(t *testing.T) {
	cmdline := "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro isolcpus=2,3 nohz_full=2-3 quiet"
	tests := []struct {
		key  string
		want string
	}{
		{"isolcpus", "2,3"},
		{"nohz_full", "2-3"},
		{"rcu_nocbs", ""},
		{"ro", ""}, // flag without value must not match
	}
	for _, tt := range tests {
		if got := cmdlineParam(cmdline, tt.key); got != tt.want {
			t.Errorf("cmdlineParam(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestDeviceIRQs(t *testing.T) {
	interrupts := `           CPU0       CPU1
  24:          0          0  IR-PCI-MSI 524288-edge      ens1f0
  25:       1234          0  IR-PCI-MSI 524289-edge      ens1f0-TxRx-0
  26:          0       5678  IR-PCI-MSI 524290-edge      ens1f0-TxRx-1
  27:          0          0  IR-PCI-MSI 524291-edge      ens1f1-TxRx-0
 NMI:          0          0  Non-maskable interrupts
 LOC:      99999      99999  Local timer interrupts
`
	got := deviceIRQs(interrupts, "ens1f0")
	want := []IRQInfo{
		{IRQ: 24, Name: "ens1f0"},
		{IRQ: 25, Name: "ens1f0-TxRx-0"},
		{IRQ: 26, Name: "ens1f0-TxRx-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("deviceIRQs() = %+v, want %+v", got, want)
	}

	if irqs := deviceIRQs(interrupts, "ens1f1"); len(irqs) != 1 || irqs[0].IRQ != 27 {
		t.Errorf("deviceIRQs(ens1f1) = %+v, want IRQ 27 only", irqs)
	}
	if irqs := deviceIRQs(interrupts, "eth9"); irqs != nil {
		t.Errorf("deviceIRQs(eth9) = %+v, want nil", irqs)
	}
}

func TestIntersects(t *testing.T) {
	if !intersects([]int{1, 2, 3}, []int{3, 4}) {
		t.Error("expected overlap on CPU 3")
	}
	if intersects([]int{1, 2}, []int{3, 4}) {
		t.Error("expected no overlap")
	}
	if intersects(nil, []int{0}) || intersects([]int{0}, nil) {
		t.Error("nil sets never overlap")
	}
}
