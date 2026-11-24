package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HPK13/proctrace/internal/event"
)

func TestSHA256AndCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(true, 0)
	reads := 0
	e.read = func(string) string { reads++; return "" }
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	for i := 0; i < 2; i++ { // second call is served from cache
		got, err := e.SHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
	if reads != 1 || len(e.cache) != 1 {
		t.Fatalf("file read %d times, cache %d entries; want 1 and 1", reads, len(e.cache))
	}
}

func TestSHA256SizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(true, 10).SHA256(path); err == nil {
		t.Fatal("expected size-limit error")
	}
}

func TestEnrichSetsOriginalName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.exe")
	if err := os.WriteFile(path, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(false, 0)
	e.read = func(string) string { return "PowerShell.EXE.MUI" }
	p := event.Process{Name: "update.exe", Executable: path}
	e.Enrich(&p)
	if p.PE == nil || p.PE.OriginalFileName != "PowerShell.EXE.MUI" {
		t.Fatalf("PE = %+v", p.PE)
	}
	if p.Hash != nil {
		t.Fatal("hash set although hashing is disabled")
	}
}