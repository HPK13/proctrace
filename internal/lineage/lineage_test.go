package lineage

import (
	"testing"
	"time"

	"github.com/HPK13/proctrace/internal/event"
)

func TestLink(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	explorer := event.Process{PID: 100, Name: "explorer.exe", Start: t0}
	reused := event.Process{PID: 100, Name: "notepad.exe", Start: t0.Add(time.Hour)}

	tests := []struct {
		name   string
		child  event.Process
		tables []Table
		want   string
		parent string
	}{
		{"verified", event.Process{PID: 200, PPID: 100, Start: t0.Add(time.Minute)},
			[]Table{NewTable([]event.Process{explorer})}, StatusVerified, "explorer.exe"},
		{"pid reused, no older candidate", event.Process{PID: 200, PPID: 100, Start: t0.Add(time.Minute)},
			[]Table{NewTable([]event.Process{reused})}, StatusPIDReused, ""},
		{"pid reused, real parent in previous scan", event.Process{PID: 200, PPID: 100, Start: t0.Add(time.Minute)},
			[]Table{NewTable([]event.Process{reused}), NewTable([]event.Process{explorer})}, StatusVerified, "explorer.exe"},
		{"parent exited", event.Process{PID: 200, PPID: 999, Start: t0},
			[]Table{NewTable([]event.Process{explorer})}, StatusExited, ""},
		{"no parent", event.Process{PID: 4, PPID: 0}, nil, StatusNone, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.child
			Link(&p, tc.tables...)
			if p.ParentStatus != tc.want {
				t.Fatalf("status = %q, want %q", p.ParentStatus, tc.want)
			}
			got := ""
			if p.Parent != nil {
				got = p.Parent.Name
			}
			if got != tc.parent {
				t.Fatalf("parent name = %q, want %q", got, tc.parent)
			}
		})
	}
}
