// Package lineage resolves and validates parent/child relationships.
//
// The parent PID the OS reports is only a number. If the real parent has
// exited, Windows (and Linux) may hand the same PID to an unrelated process,
// and naively looking it up draws a wrong process tree. Link therefore only
// accepts a candidate parent that started before the child.
package lineage

import "github.com/HPK13/proctrace/internal/event"

// Parent status values.
const (
	StatusVerified  = "verified"      // parent found and started before the child
	StatusExited    = "parent_exited" // no process with that PID is known any more
	StatusPIDReused = "pid_reused"    // a process holds the PID but started after the child
	StatusNone      = "no_parent"     // OS reports no parent (PID 0 or the process is a root)
)

// Table maps PID to process.
type Table map[int]event.Process

// NewTable indexes a process list by PID.
func NewTable(procs []event.Process) Table {
	t := make(Table, len(procs))
	for _, p := range procs {
		t[p.PID] = p
	}
	return t
}

// Link fills p.Parent and p.ParentStatus. tables are searched in order
// (typically the current snapshot, then the previous one, so a parent that
// exited between scans can still be named).
func Link(p *event.Process, tables ...Table) {
	if p.PPID <= 0 || p.PPID == p.PID {
		p.ParentStatus = StatusNone
		p.Parent = nil
		return
	}
	p.Parent = &event.Parent{PID: p.PPID}

	sawReused := false
	for _, t := range tables {
		cand, ok := t[p.PPID]
		if !ok {
			continue
		}
		if !cand.Start.IsZero() && !p.Start.IsZero() && cand.Start.After(p.Start) {
			sawReused = true
			continue
		}
		p.Parent.Name = cand.Name
		p.Parent.Executable = cand.Executable
		p.Parent.Start = cand.Start
		p.ParentStatus = StatusVerified
		return
	}
	if sawReused {
		p.ParentStatus = StatusPIDReused
	} else {
		p.ParentStatus = StatusExited
	}
}
