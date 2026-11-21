// Package config loads the agent configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Output modes.
const (
	ModeLocal   = "local"   // write events to a local JSONL file
	ModeForward = "forward" // ship events to a central HTTPS endpoint
)

// Duration is a time.Duration written as a string such as "5s" in JSON.
type Duration struct{ time.Duration }

// UnmarshalJSON parses "5s", "1m30s" and so on.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"5s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Hash controls executable hashing.
type Hash struct {
	Enabled   bool  `json:"enabled"`
	MaxFileMB int64 `json:"max_file_mb"`
}

// Local controls the local JSONL sink.
type Local struct {
	Path      string `json:"path"`
	MaxSizeMB int64  `json:"max_size_mb"`
}

// Forward controls shipping to a central collector.
type Forward struct {
	URL           string   `json:"url"`
	CAFile        string   `json:"ca_file,omitempty"`
	CertFile      string   `json:"cert_file,omitempty"`
	KeyFile       string   `json:"key_file,omitempty"`
	TokenEnv      string   `json:"token_env,omitempty"`
	SpoolPath     string   `json:"spool_path"`
	FlushInterval Duration `json:"flush_interval"`
	MaxBatchMB    int64    `json:"max_batch_mb"`
}

// Config is the whole agent configuration.
type Config struct {
	Mode         string   `json:"mode"`
	ScanInterval Duration `json:"scan_interval"`
	RulesPath    string   `json:"rules_path"`
	OnlyAlerts   bool     `json:"only_alerts"`
	Stdout       bool     `json:"stdout"`
	Hash         Hash     `json:"hash"`
	Local        Local    `json:"local"`
	Forward      Forward  `json:"forward"`
}

// Default returns a configuration for standalone use.
func Default() Config {
	return Config{
		Mode:         ModeLocal,
		ScanInterval: Duration{2 * time.Second},
		RulesPath:    "rules/default.json",
		Stdout:       true,
		Hash:         Hash{Enabled: true, MaxFileMB: 200},
		Local:        Local{Path: "proctrace-events.jsonl", MaxSizeMB: 100},
		Forward: Forward{
			SpoolPath:     "proctrace-spool.jsonl",
			FlushInterval: Duration{10 * time.Second},
			MaxBatchMB:    5,
		},
	}
}

// Load reads path over the defaults and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate checks for settings that cannot work.
func (c Config) Validate() error {
	if c.ScanInterval.Duration < 100*time.Millisecond {
		return fmt.Errorf("scan_interval must be at least 100ms")
	}
	switch c.Mode {
	case ModeLocal:
		if c.Local.Path == "" {
			return fmt.Errorf("local.path is required in local mode")
		}
	case ModeForward:
		if c.Forward.URL == "" {
			return fmt.Errorf("forward.url is required in forward mode")
		}
		if (c.Forward.CertFile == "") != (c.Forward.KeyFile == "") {
			return fmt.Errorf("forward.cert_file and forward.key_file must be set together")
		}
		if c.Forward.SpoolPath == "" {
			return fmt.Errorf("forward.spool_path is required in forward mode")
		}
		if c.Forward.FlushInterval.Duration <= 0 {
			return fmt.Errorf("forward.flush_interval must be positive")
		}
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeLocal, ModeForward, c.Mode)
	}
	return nil
}
