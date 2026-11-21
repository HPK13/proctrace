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
