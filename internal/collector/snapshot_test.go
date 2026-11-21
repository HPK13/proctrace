package collector

import (
	"context"
	"testing"
	"time"

	"github.com/HPK13/proctrace/internal/event"
)

func TestSnapshotEmitsOnlyNewProcesses(t *testing.T) {
	t0 := time.Now()
	scans := [][]event.Process{
		{{PID: 1, Name: "init", Start: t0}},
		{{PID: 1, Name: "init", Start: t0}, {PID: 2, PPID: 1, Name: "child", Start: t0.Add(time.Second)}},
	}
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	s := &Snapshot{Interval: time.Millisecond, list: func() ([]event.Process, error) {
		i := calls
		if i >= len(scans) {
			i = len(scans) - 1
			cancel()
		}
		calls++
		return scans[i], nil
	}}

	type got struct {
		name    string
		initial bool
		parent  string
	}
	var out []got
	if err := s.Run(ctx, func(p event.Process, initial bool) {
		parent := ""
		if p.Parent != nil {
			parent = p.Parent.Name
		}
		out = append(out, got{p.Name, initial, parent})
	}); err != nil {
		t.Fatal(err)
	}

	want := []got{{"init", true, ""}, {"child", false, "init"}}
	if len(out) != len(want) {
		t.Fatalf("emitted %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("emit %d = %+v, want %+v", i, out[i], want[i])
		}
	}
}
