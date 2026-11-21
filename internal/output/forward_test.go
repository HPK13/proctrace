package output

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/HPK13/proctrace/internal/config"
	"github.com/HPK13/proctrace/internal/event"
)

func TestForwarderRetriesAndDeliversOnce(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		if fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			received = append(received, sc.Text())
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	f, err := NewForwarder(config.Forward{
		URL:           srv.URL,
		SpoolPath:     filepath.Join(dir, "spool.jsonl"),
		FlushInterval: config.Duration{Duration: time.Hour}, // flush manually
		MaxBatchMB:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < 3; i++ {
		if err := f.Write(event.Event{Process: event.Process{PID: i}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if err := f.Flush(ctx); err == nil {
		t.Fatal("expected error while collector is down")
	}
	// An event written during the outage must also arrive.
	if err := f.Write(event.Event{Process: event.Process{PID: 3}}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	fail = false
	mu.Unlock()
	if err := f.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(ctx); err != nil { // nothing left: must not resend
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 4 {
		t.Fatalf("received %d events, want 4", len(received))
	}
}
