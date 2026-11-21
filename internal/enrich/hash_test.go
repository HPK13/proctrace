package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256AndCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewHasher(0)
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	for i := 0; i < 2; i++ { // second call is served from cache
		got, err := h.SHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
	if len(h.cache) != 1 {
		t.Fatalf("cache has %d entries, want 1", len(h.cache))
	}
}

func TestSHA256SizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHasher(10).SHA256(path); err == nil {
		t.Fatal("expected size-limit error")
	}
}
