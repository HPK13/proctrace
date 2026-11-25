package config

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigsLoad(t *testing.T) {
	for _, name := range []string{"local.example.json", "forward.example.json"} {
		if _, err := Load(filepath.Join("..", "..", "configs", name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateRejectsBadMode(t *testing.T) {
	c := Default()
	c.Mode = "cloud"
	if c.Validate() == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestOutputMustStayInDataDir(t *testing.T) {
	bad := []string{
		`C:\Windows\System32\drivers\etc\hosts`,
		`..\..\evil.txt`,
		`../evil`,
		`sub/events.jsonl`,
		`events.jsonl:hidden`, // NTFS alternate data stream
		`..`,
		``,
	}
	for _, name := range bad {
		c := Default()
		c.Local.Path = name
		if c.Validate() == nil {
			t.Errorf("local.path %q accepted", name)
		}
		c = Default()
		c.Mode, c.Forward.URL, c.Forward.SpoolPath = ModeForward, "https://x", name
		if c.Validate() == nil {
			t.Errorf("forward.spool_path %q accepted", name)
		}
	}
}

func TestForwardRequiresHTTPS(t *testing.T) {
	c := Default()
	c.Mode, c.Forward.URL = ModeForward, "http://collector:8080"
	if c.Validate() == nil {
		t.Fatal("plain http accepted")
	}
}

func TestResolve(t *testing.T) {
	c := Default()
	c.RulesPath = "rules.json"
	c.Resolve(filepath.FromSlash("/etc/proctrace"), filepath.FromSlash("/opt/proctrace"))
	if c.RulesPath != filepath.FromSlash("/etc/proctrace/rules.json") {
		t.Errorf("rules path %s", c.RulesPath)
	}
	if c.LocalFile() != filepath.FromSlash("/opt/proctrace/data/events.jsonl") {
		t.Errorf("local file %s", c.LocalFile())
	}
}
