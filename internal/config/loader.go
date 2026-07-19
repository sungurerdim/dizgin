// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/sungurerdim/dizgin/internal/brand"
)

// Load reads a YAML config file (path may be empty to use defaults only),
// merges environment variables, applies defaults, and validates the result.
// The caller's -c/--config flag only selects which file this reads — it is
// not a separate override layer.
//
// Precedence (highest → lowest): env vars > config file > defaults.
func Load(path string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetEnvPrefix(strings.TrimSuffix(brand.EnvPrefix, "_"))
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: read %q: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	return &cfg, nil
}

// setDefaults applies safe default values.
func setDefaults(v *viper.Viper) {
	v.SetDefault("version", 1)
	v.SetDefault("filesystem.tmp_size", "256m")
	v.SetDefault("filesystem.zero_residue", false)
	v.SetDefault("network.policy", string(NetworkOpen))
	v.SetDefault("security.no_new_privileges", true)
	v.SetDefault("security.drop_all_caps", true)
	v.SetDefault("resources.memory_mb", 0)
	v.SetDefault("resources.cpu_percent", 0)
	v.SetDefault("resources.max_pids", 0)
	// 30-minute default timeout caps runaway loops (e.g. an LLM stuck in
	// retry+backoff). Users that need long-running sessions set
	// resources.timeout: 0 to disable, or a larger value via Go duration.
	v.SetDefault("resources.timeout", 30*time.Minute)
	v.SetDefault("credential.ssh_agent", true)
	v.SetDefault("credential.git_identity", true)
	v.SetDefault("credential.github_token", true)
	v.SetDefault("monitor.level", "basic")
	v.SetDefault("monitor.interval", 10*time.Second)
}

// Validate checks Config for semantic correctness.
func (c *Config) Validate() error {
	var errs []string

	if c.Version != 1 {
		errs = append(errs, fmt.Sprintf("unsupported config version %d (expected 1)", c.Version))
	}

	switch c.Network.Policy {
	case NetworkOpen, NetworkAllowlist, NetworkBlocked, "":
		// valid
	default:
		errs = append(errs, fmt.Sprintf("unknown network.policy %q (want: open|allowlist|blocked)", c.Network.Policy))
	}

	if c.Network.Policy == NetworkAllowlist && len(c.Network.Allowlist) == 0 {
		errs = append(errs, "network.policy=allowlist requires at least one entry in network.allowlist")
	}

	if c.Resources.CPUPercent < 0 || c.Resources.CPUPercent > 100 {
		errs = append(errs, fmt.Sprintf("resources.cpu_percent must be 0-100, got %d", c.Resources.CPUPercent))
	}

	if c.Resources.MemoryMB < 0 {
		errs = append(errs, fmt.Sprintf("resources.memory_mb must be >= 0, got %d", c.Resources.MemoryMB))
	}

	if c.Resources.MaxPIDs < 0 {
		errs = append(errs, fmt.Sprintf("resources.max_pids must be >= 0, got %d", c.Resources.MaxPIDs))
	}

	if c.Resources.Timeout < 0 {
		errs = append(errs, fmt.Sprintf("resources.timeout must be >= 0, got %v", c.Resources.Timeout))
	}

	switch c.Monitor.Level {
	case "basic", "detailed", "full", "":
		// valid
	default:
		errs = append(errs, fmt.Sprintf("monitor.level must be basic|detailed|full, got %q", c.Monitor.Level))
	}

	if c.Monitor.Interval < 0 {
		errs = append(errs, fmt.Sprintf("monitor.interval must be >= 0, got %v", c.Monitor.Interval))
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
