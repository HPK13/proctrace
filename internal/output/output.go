// Package output delivers events to their destination.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/HPK13/proctrace/internal/event"
)

// Sink receives events.
type Sink interface {
	Write(ev event.Event) error
	Close() error
}

// Writer writes one JSON object per line to an io.Writer (e.g. stdout).
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewWriter returns a JSONL sink on w.
func NewWriter(w io.Writer) *Writer { return &Writer{enc: json.NewEncoder(w)} }

// Write encodes ev.
func (s *Writer) Write(ev event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(ev)
}

// Close is a no-op.
func (s *Writer) Close() error { return nil }

// File appends JSONL to a file and rotates it to path+".1" at maxBytes.
// The format is what Filebeat, the Wazuh agent or Fluent Bit expect when
// tailing a JSON log.
type File struct {
	path     string
	maxBytes int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenFile opens (or creates) the log at path.
func OpenFile(path string, maxBytes int64) (*File, error) {
	s := &File{path: path, maxBytes: maxBytes}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *File) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.size = f, fi.Size()
	return nil
}

// Write appends ev as one line.
func (s *File) Write(ev event.Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBytes > 0 && s.size+int64(len(line)) > s.maxBytes && s.size > 0 {
		if err := s.rotate(); err != nil {
			return fmt.Errorf("rotate %s: %w", s.path, err)
		}
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	return err
}

func (s *File) rotate() error {
	if err := s.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		return err
	}
	return s.open()
}

// Close closes the file.
func (s *File) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
