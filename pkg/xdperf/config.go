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
	Count       int
	PPS         uint64        // 0 = unlimited (max speed)
	Duration    time.Duration // 0 = not specified (use count instead)

	DebugMode    int
	ShowNICStats bool // show NIC-level statistics (may include other traffic on the same interface)
}

func (c *Config) Validate() error {
	if c.PluginName == "" {
		return fmt.Errorf("plugin name is required")
	}
	if c.Device == "" {
		return fmt.Errorf("device is required")
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
	if c.Count < 0 {
		return fmt.Errorf("count must be non-negative")
	}
	if c.Duration < 0 {
		return fmt.Errorf("duration must be non-negative")
	}

	// Either count or duration must be specified
	if c.Count == 0 && c.Duration == 0 {
		return fmt.Errorf("either --count or --duration must be specified")
	}

	// Cannot specify both count and duration
	if c.Count > 0 && c.Duration > 0 {
		return fmt.Errorf("cannot specify both --count and --duration")
	}

	// Duration requires PPS
	if c.Duration > 0 && c.PPS == 0 {
		return fmt.Errorf("--duration requires --pps to be specified")
	}

	if c.PluginLanguage == "" {
		sp := strings.Split(c.PluginName, ".")
		if len(sp) != 2 {
			return fmt.Errorf("invalid plugin name format, must be <name>.<lang>")
		}
		c.PluginLanguage = strings.ToLower(sp[1])
	}

	// parallelism and count check (only when count is specified)
	// count は全体の投げるパケットの数
	// parallelism は並列数
	// なので、 count > 0 の場合は count >= parallelism である必要があります
	if c.Count > 0 && c.Count < c.Parallelism {
		return fmt.Errorf("count must be greater than or equal to parallelism")
	}

	return nil
}
