// Package enrich adds context to observed processes.
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

// Hasher computes SHA-256 hashes of process images, caching by
// path + size + modification time so each binary is read only once.
type Hasher struct {
	MaxFileSize int64 // files larger than this are skipped; 0 = no limit

	mu    sync.Mutex
	cache map[string]string
}

// NewHasher returns a Hasher that skips files above maxFileSize bytes.
func NewHasher(maxFileSize int64) *Hasher {
	return &Hasher{MaxFileSize: maxFileSize, cache: map[string]string{}}
}

// SHA256 returns the hex SHA-256 of the file at path.
func (h *Hasher) SHA256(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if h.MaxFileSize > 0 && fi.Size() > h.MaxFileSize {
		return "", fmt.Errorf("%s exceeds hash size limit", path)
	}
	key := fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())

	h.mu.Lock()
	if sum, ok := h.cache[key]; ok {
		h.mu.Unlock()
		return sum, nil
	}
	h.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(d.Sum(nil))

	h.mu.Lock()
	if len(h.cache) >= maxCacheEntries {
		h.cache = map[string]string{}
	}
	h.cache[key] = sum
	h.mu.Unlock()
	return sum, nil
}

// Enrich sets p.Hash when the executable can be read. Failures are silent:
// a missing hash is normal for protected or already-exited processes.
func (h *Hasher) Enrich(p *event.Process) {
	if p.Executable == "" {
		return
	}
	if sum, err := h.SHA256(p.Executable); err == nil {
		p.Hash = &event.Hash{SHA256: sum}
	}
}
