// Package collector produces process observations.
//
// v0 ships a polling Snapshot collector, which works everywhere but can miss
// processes that live shorter than the scan interval. The planned ETW
// collector (Microsoft-Windows-Kernel-Process) will implement the same
// Collector interface and receive every process start as it happens.
package collector

import (
	"context"
	"log"
	"time"

	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/lineage"
)

// EmitFunc receives each observed process. initial is true for processes
// that were already running when collection started.
type EmitFunc func(p event.Process, initial bool)

// Collector is implemented by every event source.
type Collector interface {
	Run(ctx context.Context, emit EmitFunc) error
}

// Snapshot polls the OS process table and emits processes it has not seen.
type Snapshot struct {
	Interval time.Duration
	list     func() ([]event.Process, error)
}

// NewSnapshot returns a polling collector for the current platform.
func NewSnapshot(interval time.Duration) *Snapshot {
	return &Snapshot{Interval: interval, list: listProcesses}
}

type procKey struct {
	pid   int
	start int64
}

func keyOf(p event.Process) procKey {
	return procKey{pid: p.PID, start: p.Start.UnixNano()}
}

// Once takes a single snapshot and returns every process, with parents linked.
func (s *Snapshot) Once() ([]event.Process, error) {
	procs, err := s.list()
	if err != nil {
		return nil, err
	}
	table := lineage.NewTable(procs)
	for i := range procs {
		lineage.Link(&procs[i], table)
	}
	return procs, nil
}

// Run scans until ctx is cancelled. A failed first scan is returned as an
// error; later failures are logged and retried on the next tick.
func (s *Snapshot) Run(ctx context.Context, emit EmitFunc) error {
	var prev lineage.Table
	seen := map[procKey]bool{}
	first := true

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		procs, err := s.list()
		switch {
		case err != nil && first:
			return err
		case err != nil:
			log.Printf("collector: scan failed: %v", err)
		default:
			cur := lineage.NewTable(procs)
			next := make(map[procKey]bool, len(procs))
			for _, p := range procs {
				k := keyOf(p)
				next[k] = true
				if seen[k] {
					continue
				}
				lineage.Link(&p, cur, prev)
				emit(p, first)
			}
			seen, prev, first = next, cur, false
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
