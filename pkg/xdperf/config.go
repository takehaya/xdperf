package xdperf

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/logger"
)

type Config struct {
	LoggerConfig logger.Config

	// From For CLI Flags
	PluginPath       string
	PluginName       string
	PluginLanguage   string
	PluginConfig     string
	PluginConfigPath string

	Sender      bool
	Receiver    bool
	SwapResp    bool
	Device      string
	Parallelism int
	Count       uint64        // total packets to send
	PPS         uint64        // 0 = unlimited (max speed)
	Duration    time.Duration // 0 = not specified (use count instead)
	Infinite    bool          // enable infinite mode for maximum throughput
	BatchSize   uint32        // syscall batch size tuning (default: 1)

	DebugMode int

	ShowNICStats bool   // show NIC-level statistics (may include other traffic on the same interface)
	WasmCacheDir string // WASM compilation cache directory (empty = default ~/.cache/xdperf/wasm/)
	CPUMode      string // NUMA-aware CPU selection mode (auto/local/balanced/node:N/CPU list)
}

// Normalize fills in config fields derived from user input (currently
// PluginLanguage, parsed from a "<name>.<lang>" PluginName). It is idempotent
// and only mutates the receiver; call it before Validate. Keeping the derivation
// here — rather than hidden inside Validate — makes Validate side-effect-free.
func (c *Config) Normalize() {
	if c.PluginLanguage != "" {
		return
	}
	if sp := strings.Split(c.PluginName, "."); len(sp) == 2 {
		c.PluginLanguage = strings.ToLower(sp[1])
	}
}

func (c *Config) Validate() error {
	if c.Device == "" {
		return fmt.Errorf("device is required")
	}

	// Server mode (recv only) doesn't require sender-specific validations
	if !c.Sender && c.Receiver {
		return nil
	}

	// Sender-specific validations
	if c.PluginName == "" {
		return fmt.Errorf("plugin name is required")
	}
	if c.Parallelism <= 0 {
		return fmt.Errorf("parallelism must be positive")
	}
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible CPU count: %w", err)
	}
	if c.Parallelism > numCPU {
		return fmt.Errorf("parallelism (%d) exceeds available CPU cores (%d)", c.Parallelism, numCPU)
	}
	if c.Duration < 0 {
		return fmt.Errorf("duration must be non-negative")
	}

	// Infinite mode validation (must be checked before count/duration validation)
	if c.Infinite {
		if !c.Sender {
			return fmt.Errorf("--infinite requires --send to be specified")
		}
		if c.Count <= 0 {
			return fmt.Errorf("--infinite requires --count to be specified (used as packet pool size)")
		}
		if c.Duration > 0 {
			return fmt.Errorf("--infinite cannot be used with --duration")
		}
		// Note: --pps is ignored in infinite mode (always max speed)
	} else {
		// Non-infinite mode: either count or duration must be specified
		if c.Count == 0 && c.Duration == 0 {
			return fmt.Errorf("either --count or --duration must be specified")
		}

		// Cannot specify both count and duration
		if c.Count > 0 && c.Duration > 0 {
			return fmt.Errorf("cannot specify both --count and --duration")
		}
	}

	// Duration requires PPS
	if c.Duration > 0 && c.PPS == 0 {
		return fmt.Errorf("--duration requires --pps to be specified")
	}

	// PluginLanguage is derived by Normalize; if it is still empty here, the
	// PluginName was not in "<name>.<lang>" form (and no language was set).
	// Validate the invariant without mutating.
	if c.PluginLanguage == "" {
		if sp := strings.Split(c.PluginName, "."); len(sp) != 2 {
			return fmt.Errorf("invalid plugin name format, must be <name>.<lang>")
		}
	}

	// parallelism and count check (only when count is specified)
	// count は全体の投げるパケットの数
	// parallelism は並列数
	// なので、 count > 0 の場合は count >= parallelism である必要があります
	if c.Count > 0 && c.Count < uint64(c.Parallelism) {
		return fmt.Errorf("count must be greater than or equal to parallelism")
	}

	return nil
}
