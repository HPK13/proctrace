// Package event defines the records proctrace produces.
//
// Field names follow the Elastic Common Schema (ECS) where an ECS field
// exists (process.*, event.*, host.*), so events can be ingested by Elastic,
// Wazuh, OpenSearch or Sentinel without a custom parser. Anything that is
// specific to proctrace lives under the "proctrace" key.
package event

import (
	"os"
	"runtime"
	"time"
)

// Hash holds file hashes of a process image.
type Hash struct {
	SHA256 string `json:"sha256,omitempty"`
}

// PE holds metadata from a Windows executable's version resource (ECS
// process.pe.*). OriginalFileName is set by the publisher at build time and
// survives renaming the file, so it exposes renamed system tools.
type PE struct {
	OriginalFileName string `json:"original_file_name,omitempty"`
}

// Parent is the subset of process fields recorded for a parent process.
type Parent struct {
	PID        int       `json:"pid"`
	Name       string    `json:"name,omitempty"`
	Executable string    `json:"executable,omitempty"`
	Start      time.Time `json:"start,omitzero"`
}

// Process describes one observed process (ECS process.*).
type Process struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	Executable  string    `json:"executable,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	Start       time.Time `json:"start,omitzero"`
	Hash        *Hash     `json:"hash,omitempty"`
	PE          *PE       `json:"pe,omitempty"`
	Parent      *Parent   `json:"parent,omitempty"`

	// PPID is the parent PID as reported by the OS. It is not trusted on
	// its own: lineage.Link validates it and fills Parent.
	PPID int `json:"-"`
	// ParentStatus is set by lineage.Link (see lineage.Status* constants).
	ParentStatus string `json:"-"`
}

// Detection is one rule that matched a process.
type Detection struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Score    int      `json:"score"`
	Attack   []string `json:"attack,omitempty"`
	Reason   string   `json:"reason"`
}

// Meta is the ECS event.* block.
type Meta struct {
	Kind      string   `json:"kind"`
	Category  []string `json:"category"`
	Type      []string `json:"type"`
	Action    string   `json:"action"`
	RiskScore int      `json:"risk_score"`
}

// Agent identifies the producer (ECS agent.*).
type Agent struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

// OS is ECS host.os.*.
type OS struct {
	Type string `json:"type"`
}

// Host is ECS host.*.
type Host struct {
	Hostname string `json:"hostname"`
	OS       OS     `json:"os"`
}

// Analysis carries proctrace-specific results.
type Analysis struct {
	ParentStatus string      `json:"parent_status"`
	Detections   []Detection `json:"detections,omitempty"`
}

// Event is one output record.
type Event struct {
	Timestamp time.Time `json:"@timestamp"`
	Agent     Agent     `json:"agent"`
	Host      Host      `json:"host"`
	Event     Meta      `json:"event"`
	Process   Process   `json:"process"`
	Proctrace Analysis  `json:"proctrace"`
}

// LocalHost returns the host block for the machine the agent runs on.
func LocalHost() Host {
	name, _ := os.Hostname()
	return Host{Hostname: name, OS: OS{Type: runtime.GOOS}}
}

// New builds an Event. initial marks processes that were already running
// when the agent started (ECS event.type "info") as opposed to newly
// started ones ("start").
func New(p Process, dets []Detection, score int, initial bool, host Host, version string) Event {
	meta := Meta{
		Kind:      "event",
		Category:  []string{"process"},
		Type:      []string{"start"},
		Action:    "process-started",
		RiskScore: score,
	}
	if initial {
		meta.Type = []string{"info"}
		meta.Action = "process-observed"
	}
	if len(dets) > 0 {
		meta.Kind = "alert"
	}
	return Event{
		Timestamp: time.Now().UTC(),
		Agent:     Agent{Name: "proctrace", Type: "endpoint", Version: version},
		Host:      host,
		Event:     meta,
		Process:   p,
		Proctrace: Analysis{ParentStatus: p.ParentStatus, Detections: dets},
	}
}