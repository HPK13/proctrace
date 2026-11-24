// Package harden checks that an elevated agent is not running from files a
// non-admin user can change.
//
// If proctrace runs as Administrator (or root) but its executable, config,
// rules or data folder can be modified by an ordinary user, then malware
// running as that user can swap the binary or edit the config and have its
// code or file writes carried out with admin rights. That is a local
// privilege-escalation path, so the agent refuses to start in that state.
package harden

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Target is a file or folder the agent depends on.
type Target struct {
	Path string
	Dir  bool   // Path is a folder
	Role string // what it is, for messages ("executable", "config", ...)
}

// Check returns one message per problem found. A file's parent folder is
// checked too, since write access to the folder lets a user replace the
// file. An empty result means every target is admin-only.
func Check(targets []Target) []string {
	seen := map[string]bool{}
	var problems []string
	check := func(path, role string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		reason, err := writableByOthers(path)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s %s: cannot check permissions: %v", role, path, err))
		case reason != "":
			problems = append(problems, fmt.Sprintf("%s %s is %s", role, path, reason))
		}
	}
	for _, t := range targets {
		p, err := filepath.Abs(t.Path)
		if err != nil {
			p = t.Path
		}
		check(p, t.Role)
		if !t.Dir {
			check(filepath.Dir(p), t.Role+" folder")
		}
	}
	sort.Strings(problems)
	return problems
}