//go:build !windows

package harden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership checks need root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	targets := []Target{{Path: file, Role: "rules"}}
	if p := Check(targets); len(p) != 0 {
		t.Fatalf("root-owned 0644 file reported: %v", p)
	}

	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if p := Check(targets); len(p) != 1 || !strings.Contains(p[0], "writable by group or others") {
		t.Fatalf("world-writable file: %v", p)
	}

	os.Chmod(file, 0o644)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if p := Check(targets); len(p) != 1 || !strings.Contains(p[0], "rules folder") {
		t.Fatalf("world-writable folder: %v", p)
	}
}