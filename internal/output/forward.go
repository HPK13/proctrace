package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/HPK13/proctrace/internal/config"
	"github.com/HPK13/proctrace/internal/event"
)

// Forwarder ships events to an HTTPS endpoint as NDJSON
// (Content-Type: application/x-ndjson). Any collector with an HTTP input
// works: Vector, Fluent Bit, Logstash, or a small custom server.
//
// Events are always written to a local spool file first. On each flush the
// spool is renamed to an "inflight" file and sent; the inflight file is
// deleted only after a 2xx response, so events survive network outages and
// agent restarts. Writes never wait on the network.
type Forwarder struct {
	cfg    config.Forward
	client *http.Client
	token  string
	spool  *File

	sendMu sync.Mutex // serialises flushes
	cancel context.CancelFunc
	done   chan struct{}
}

// NewForwarder builds the TLS client, opens the spool and starts flushing.
func NewForwarder(cfg config.Forward) (*Forwarder, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert} // mutual TLS
	}

	spool, err := OpenFile(cfg.SpoolPath, 0)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
		},
		spool:  spool,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if cfg.TokenEnv != "" {
		f.token = os.Getenv(cfg.TokenEnv)
	}
	go f.loop(ctx)
	return f, nil
}

// Write appends ev to the spool.
func (f *Forwarder) Write(ev event.Event) error { return f.spool.Write(ev) }

// Close makes a final flush attempt and stops the background loop.
func (f *Forwarder) Close() error {
	f.cancel()
	<-f.done
	if err := f.Flush(context.Background()); err != nil {
		log.Printf("forward: final flush failed, events stay spooled: %v", err)
	}
	return f.spool.Close()
}

func (f *Forwarder) loop(ctx context.Context) {
	defer close(f.done)
	t := time.NewTicker(f.cfg.FlushInterval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := f.Flush(ctx); err != nil {
				log.Printf("forward: %v (will retry)", err)
			}
		}
	}
}

func (f *Forwarder) inflightPath() string { return f.cfg.SpoolPath + ".inflight" }

// Flush sends any pending inflight batch, then the current spool.
func (f *Forwarder) Flush(ctx context.Context) error {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()

	if err := f.sendInflight(ctx); err != nil {
		return err
	}
	if err := f.rotateSpool(); err != nil {
		return err
	}
	return f.sendInflight(ctx)
}

func (f *Forwarder) rotateSpool() error {
	f.spool.mu.Lock()
	defer f.spool.mu.Unlock()
	if f.spool.size == 0 {
		return nil
	}
	if err := f.spool.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.spool.path, f.inflightPath()); err != nil {
		_ = f.spool.open()
		return err
	}
	return f.spool.open()
}

func (f *Forwarder) sendInflight(ctx context.Context) error {
	file, err := os.Open(f.inflightPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	limit := f.cfg.MaxBatchMB << 20
	if limit <= 0 {
		limit = 5 << 20
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	file.Close()
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		// Trim to the last complete line; the remainder is sent next flush.
		cut := bytes.LastIndexByte(body[:limit], '\n') + 1
		if cut == 0 {
			return fmt.Errorf("single event larger than max_batch_mb")
		}
		body = body[:cut]
	}
	if len(body) == 0 {
		return os.Remove(f.inflightPath())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector returned %s", resp.Status)
	}
	return f.dropSent(len(body))
}

// dropSent removes the first n bytes (just delivered) from the inflight file.
func (f *Forwarder) dropSent(n int) error {
	data, err := os.ReadFile(f.inflightPath())
	if err != nil {
		return err
	}
	if n >= len(data) {
		return os.Remove(f.inflightPath())
	}
	return os.WriteFile(f.inflightPath(), data[n:], 0o600)
}
