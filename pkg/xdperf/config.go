package xdperf

import (
	"fmt"
	"strings"

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

	DebugMode int
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
	if c.Count <= 0 {
		return fmt.Errorf("count must be positive")
	}
	if c.PluginLanguage == "" {
		sp := strings.Split(c.PluginName, ".")
		if len(sp) != 2 {
			return fmt.Errorf("invalid plugin name format, must be <name>.<lang>")
		}
		c.PluginLanguage = strings.ToLower(sp[1])
	}

	// parallelism and count check
	// count は全体の投げるパケットの数
	// parallelism は並列数
	// なので、 count >= parallelism である必要があります
	if c.Count < c.Parallelism {
		return fmt.Errorf("count must be greater than or equal to parallelism")
	}

	return nil
}
