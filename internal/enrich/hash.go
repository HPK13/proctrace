// Package enrich adds file-based context to observed processes: the SHA-256
// of the executable and, on Windows, its PE OriginalFileName.
package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/HPK13/proctrace/internal/event"
)

// maxCacheEntries bounds memory use; the cache is simply reset when full.
const maxCacheEntries = 10000

type facts struct {
	sha256   string
	original string
}

// Enricher looks up facts about executables, caching them by
// path + size + modification time so each binary is read only once.
type Enricher struct {
	Hash        bool  // compute SHA-256
	MaxFileSize int64 // skip hashing files larger than this; 0 = no limit

	mu    sync.Mutex
	cache map[string]facts
	read  func(string) string // OriginalFileName reader (swappable in tests)
}

// New returns an Enricher. hash enables SHA-256; files larger than
// maxFileSize bytes are not hashed.
func New(hash bool, maxFileSize int64) *Enricher {
	return &Enricher{Hash: hash, MaxFileSize: maxFileSize, cache: map[string]facts{}, read: originalFileName}
}

func (e *Enricher) lookup(path string) (facts, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return facts{}, err
	}
	if !fi.Mode().IsRegular() {
		return facts{}, fmt.Errorf("%s is not a regular file", path)
	}
	key := fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())

	e.mu.Lock()
	f, ok := e.cache[key]
	e.mu.Unlock()
	if ok {
		return f, nil
	}

	f.original = e.read(path)
	if e.Hash && (e.MaxFileSize <= 0 || fi.Size() <= e.MaxFileSize) {
		if sum, err := hashFile(path); err == nil {
			f.sha256 = sum
		}
	}

	e.mu.Lock()
	if len(e.cache) >= maxCacheEntries {
		e.cache = map[string]facts{}
	}
	e.cache[key] = f
	e.mu.Unlock()
	return f, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(d.Sum(nil)), nil
}

// SHA256 returns the hex SHA-256 of the file at path, or an error if it
// cannot be read or is over the size limit.
func (e *Enricher) SHA256(path string) (string, error) {
	f, err := e.lookup(path)
	if err != nil {
		return "", err
	}
	if f.sha256 == "" {
		return "", fmt.Errorf("%s was not hashed (disabled or over size limit)", path)
	}
	return f.sha256, nil
}

// Enrich sets p.Hash and p.PE when the executable can be read. Failures are
// silent: missing facts are normal for protected or already-exited processes.
func (e *Enricher) Enrich(p *event.Process) {
	if p.Executable == "" {
		return
	}
	f, err := e.lookup(p.Executable)
	if err != nil {
		return
	}
	if f.sha256 != "" {
		p.Hash = &event.Hash{SHA256: f.sha256}
	}
	if f.original != "" {
		p.PE = &event.PE{OriginalFileName: f.original}
	}
}