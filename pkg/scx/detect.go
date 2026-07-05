// Package scx integrates xdperf with sched_ext, the eBPF CPU scheduler
// framework (kernel >= 6.12). This file is detection only and safe to call on
// any kernel; the scheduler itself is loaded elsewhere and strictly opt-in.
package scx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/btf"
)

const sysfsRoot = "/sys/kernel/sched_ext"

// requiredKfunc is the dispatch kfunc under its 6.13+ name
// (scx_bpf_dispatch was renamed to scx_bpf_dsq_insert in 6.13). Its presence
// in kernel BTF separates a kernel xdperf can drive from a 6.12 one.
const requiredKfunc = "scx_bpf_dsq_insert"

// Info is a point-in-time view of kernel sched_ext support.
type Info struct {
	Available bool   `json:"available"`          // CONFIG_SCHED_EXT=y (sysfs root present)
	State     string `json:"state,omitempty"`    // "enabled" while a BPF scheduler runs, else "disabled"
	RootOps   string `json:"root_ops,omitempty"` // name of the currently running scheduler
	KfuncOK   bool   `json:"kfunc_ok"`           // 6.13+ kfunc names present in kernel BTF
}

// Detect inspects sysfs and kernel BTF. It never fails: absence is data.
func Detect() Info {
	info := Info{}
	if _, err := os.Stat(sysfsRoot); err != nil {
		return info
	}
	info.Available = true
	info.State = readSysfs("state")
	info.RootOps = readSysfs("root/ops")
	if spec, err := btf.LoadKernelSpec(); err == nil {
		var fn *btf.Func
		if err := spec.TypeByName(requiredKfunc, &fn); err == nil {
			info.KfuncOK = true
		}
	}
	return info
}

func readSysfs(rel string) string {
	b, err := os.ReadFile(filepath.Join(sysfsRoot, rel))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Supported returns nil when xdperf's sched_ext scheduler can run on this
// kernel, or a specific reason otherwise.
func Supported() error {
	return supported(Detect())
}

func supported(info Info) error {
	if !info.Available {
		return fmt.Errorf("sched_ext is not available on this kernel (requires kernel >= 6.12 with CONFIG_SCHED_EXT=y)")
	}
	if !info.KfuncOK {
		return fmt.Errorf("sched_ext is present but predates the %s kfunc; xdperf requires kernel >= 6.13", requiredKfunc)
	}
	return nil
}
