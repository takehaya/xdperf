package xdperf

import (
	"fmt"

	"github.com/takehaya/xdperf/pkg/logger"
)

type Config struct {
	LoggerConfig logger.Config

	// From For CLI Flags
	PluginPath         string
	PluginName         string
	PluginConfig       string
	LoadedPluginConfig map[string]interface{} // internal use only
	ServerFlag         bool
	Device             string
	Parallelism        int
	Count              int
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
	if c.Count <= 0 {
		return fmt.Errorf("count must be positive")
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
