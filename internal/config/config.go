// Package config loads the agent configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Privacy controls what of each command line is kept.
type Privacy struct {
	RedactCommandLines bool `json:"redact_command_lines"` // mask passwords and tokens
	DropCommandLines   bool `json:"drop_command_lines"`   // do not record command lines at all
	MaxCommandLine     int  `json:"max_command_line"`     // truncate to this many bytes; 0 = no limit
}

// Local controls the local JSONL sink.
type Local struct {
	Path      string `json:"path"` // file name inside data_dir
	MaxSizeMB int64  `json:"max_size_mb"`
}

// Forward controls shipping to a central collector.
type Forward struct {
	URL           string   `json:"url"`
	CAFile        string   `json:"ca_file,omitempty"`
	CertFile      string   `json:"cert_file,omitempty"`
	KeyFile       string   `json:"key_file,omitempty"`
	TokenEnv      string   `json:"token_env,omitempty"`
	SpoolPath     string   `json:"spool_path"` // file name inside data_dir
	FlushInterval Duration `json:"flush_interval"`
	MaxBatchMB    int64    `json:"max_batch_mb"`
}

// Config is the whole agent configuration.
type Config struct {
	Mode         string   `json:"mode"`
	ScanInterval Duration `json:"scan_interval"`
	RulesPath    string   `json:"rules_path,omitempty"` // empty = rules built into the binary
	DataDir      string   `json:"data_dir"`             // where all output files live
	OnlyAlerts   bool     `json:"only_alerts"`
	Stdout       bool     `json:"stdout"`
	Hash         Hash     `json:"hash"`
	Privacy      Privacy  `json:"privacy"`
	Local        Local    `json:"local"`
	Forward      Forward  `json:"forward"`
}

// Default returns a configuration for standalone use.
func Default() Config {
	return Config{
		Mode:         ModeLocal,
		ScanInterval: Duration{2 * time.Second},
		DataDir:      "data",
		Stdout:       true,
		Hash:         Hash{Enabled: true, MaxFileMB: 200},
		Privacy:      Privacy{RedactCommandLines: true, MaxCommandLine: 4096},
		Local:        Local{Path: "events.jsonl", MaxSizeMB: 100},
		Forward: Forward{
			SpoolPath:     "spool.jsonl",
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

// plainFileName rejects anything but a bare file name, so a config value
// can never make the agent write outside data_dir: no folders, no "..",
// no drive letters and no NTFS alternate data streams ("file:stream").
func plainFileName(key, name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\:`) || filepath.Base(name) != name {
		return fmt.Errorf("%s must be a plain file name inside data_dir, got %q", key, name)
	}
	return nil
}

// Validate checks for settings that cannot work or are unsafe.
func (c Config) Validate() error {
	if c.ScanInterval.Duration < 100*time.Millisecond {
		return fmt.Errorf("scan_interval must be at least 100ms")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if c.Privacy.MaxCommandLine < 0 {
		return fmt.Errorf("privacy.max_command_line must not be negative")
	}
	switch c.Mode {
	case ModeLocal:
		if err := plainFileName("local.path", c.Local.Path); err != nil {
			return err
		}
	case ModeForward:
		if c.Forward.URL == "" {
			return fmt.Errorf("forward.url is required in forward mode")
		}
		if !strings.HasPrefix(strings.ToLower(c.Forward.URL), "https://") {
			return fmt.Errorf("forward.url must use https://")
		}
		if (c.Forward.CertFile == "") != (c.Forward.KeyFile == "") {
			return fmt.Errorf("forward.cert_file and forward.key_file must be set together")
		}
		if err := plainFileName("forward.spool_path", c.Forward.SpoolPath); err != nil {
			return err
		}
		if c.Forward.FlushInterval.Duration <= 0 {
			return fmt.Errorf("forward.flush_interval must be positive")
		}
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeLocal, ModeForward, c.Mode)
	}
	return nil
}

// Resolve makes paths absolute: rules and certificate paths relative to the
// config file's folder, data_dir relative to the executable's folder (never
// the current directory, which whoever starts the agent controls).
func (c *Config) Resolve(configDir, exeDir string) {
	abs := func(base, p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.RulesPath = abs(configDir, c.RulesPath)
	c.Forward.CAFile = abs(configDir, c.Forward.CAFile)
	c.Forward.CertFile = abs(configDir, c.Forward.CertFile)
	c.Forward.KeyFile = abs(configDir, c.Forward.KeyFile)
	c.DataDir = abs(exeDir, c.DataDir)
}

// LocalFile is the full path of the local event log.
func (c Config) LocalFile() string { return filepath.Join(c.DataDir, c.Local.Path) }

// SpoolFile is the full path of the forwarder's spool.
func (c Config) SpoolFile() string { return filepath.Join(c.DataDir, c.Forward.SpoolPath) }
