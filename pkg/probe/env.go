package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/takehaya/xdperf/pkg/numa"
	"github.com/takehaya/xdperf/pkg/scx"
	"golang.org/x/sys/unix"
)

// SchedExtInfo reports kernel sched_ext support and whether xdperf's --scx
// isolation can run on it.
type SchedExtInfo struct {
	Available bool   `json:"available"`
	State     string `json:"state,omitempty"`
	RootOps   string `json:"root_ops,omitempty"`
	ScxUsable bool   `json:"scx_usable"`
	Reason    string `json:"reason,omitempty"`
}

// IRQInfo is one hardware IRQ that belongs to the probed device, with the
// CPUs its affinity currently points at.
type IRQInfo struct {
	IRQ      int    `json:"irq"`
	Name     string `json:"name"`
	CPUs     []int  `json:"cpus,omitempty"`
	Overlaps bool   `json:"overlaps_selected"`
}

// EnvResult collects read-only environment facts that shape TX jitter:
// scheduler support, RT throttling, CPU frequency governors, IRQ layout and
// boot-time isolation. All fields are best-effort.
type EnvResult struct {
	KernelRelease     string         `json:"kernel_release"`
	SchedExt          SchedExtInfo   `json:"sched_ext"`
	RTRuntimeUs       string         `json:"sched_rt_runtime_us,omitempty"`
	SelectedCPUs      []int          `json:"selected_cpus,omitempty"`
	CPUSelectionError string         `json:"cpu_selection_error,omitempty"`
	CPUGovernors      map[int]string `json:"cpu_governors,omitempty"`
	IRQBalanceRunning bool           `json:"irqbalance_running"`
	IsolCPUs          string         `json:"isolcpus,omitempty"`
	NohzFull          string         `json:"nohz_full,omitempty"`
	RCUNocbs          string         `json:"rcu_nocbs,omitempty"`
	DeviceIRQs        []IRQInfo      `json:"device_irqs,omitempty"`
}

// ProbeEnv gathers the environment facts for deviceName as the run command
// would see them: cpuMode/parallelism go through the same numa.SelectCPUs so
// the governor and IRQ-overlap checks look at the actual worker CPUs.
func ProbeEnv(deviceName, cpuMode string, parallelism int) *EnvResult {
	env := &EnvResult{}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		env.KernelRelease = unix.ByteSliceToString(uts.Release[:])
	}

	info := scx.Detect()
	env.SchedExt = SchedExtInfo{
		Available: info.Available,
		State:     info.State,
		RootOps:   info.RootOps,
	}
	if err := scx.Supported(); err != nil {
		env.SchedExt.Reason = err.Error()
	} else {
		env.SchedExt.ScxUsable = true
	}

	if b, err := os.ReadFile("/proc/sys/kernel/sched_rt_runtime_us"); err == nil {
		env.RTRuntimeUs = strings.TrimSpace(string(b))
	}

	cpus, err := numa.SelectCPUs(cpuMode, parallelism, deviceName)
	if err != nil {
		env.CPUSelectionError = err.Error()
	} else {
		env.SelectedCPUs = cpus
		env.CPUGovernors = readGovernors(cpus)
	}

	env.IRQBalanceRunning = processRunning("irqbalance")

	if b, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(b)
		env.IsolCPUs = cmdlineParam(cmdline, "isolcpus")
		env.NohzFull = cmdlineParam(cmdline, "nohz_full")
		env.RCUNocbs = cmdlineParam(cmdline, "rcu_nocbs")
	}

	if b, err := os.ReadFile("/proc/interrupts"); err == nil {
		for _, irq := range deviceIRQs(string(b), deviceName) {
			if cpuList, err := os.ReadFile(fmt.Sprintf("/proc/irq/%d/smp_affinity_list", irq.IRQ)); err == nil {
				if cpus, err := numa.ParseCPUList(strings.TrimSpace(string(cpuList))); err == nil {
					irq.CPUs = cpus
					irq.Overlaps = intersects(cpus, env.SelectedCPUs)
				}
			}
			env.DeviceIRQs = append(env.DeviceIRQs, irq)
		}
	}

	return env
}

func readGovernors(cpus []int) map[int]string {
	govs := make(map[int]string, len(cpus))
	for _, cpu := range cpus {
		path := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", cpu)
		b, err := os.ReadFile(path)
		if err != nil {
			continue // no cpufreq driver (e.g. some VMs)
		}
		govs[cpu] = strings.TrimSpace(string(b))
	}
	if len(govs) == 0 {
		return nil
	}
	return govs
}

// processRunning reports whether a process with exactly this comm exists.
func processRunning(comm string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == comm {
			return true
		}
	}
	return false
}

// cmdlineParam extracts the value of key=... from a kernel command line.
func cmdlineParam(cmdline, key string) string {
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

// deviceIRQs parses /proc/interrupts content and returns the IRQs whose
// action name belongs to deviceName (e.g. "ens1f0-TxRx-3" or plain "ens1f0").
// CPU affinity is filled in by the caller from /proc/irq/<n>/.
func deviceIRQs(interrupts, deviceName string) []IRQInfo {
	var out []IRQInfo
	for _, line := range strings.Split(interrupts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		num, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			continue // header or software rows (NMI, LOC, ...)
		}
		name := fields[len(fields)-1]
		if name != deviceName && !strings.HasPrefix(name, deviceName+"-") && !strings.HasPrefix(name, deviceName+"@") {
			continue
		}
		out = append(out, IRQInfo{IRQ: num, Name: name})
	}
	return out
}

func intersects(a, b []int) bool {
	set := make(map[int]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}
