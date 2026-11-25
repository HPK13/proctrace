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
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
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

// ServiceSID returns the SID Windows assigns to a service, such as
// TrustedInstaller: S-1-5-80- followed by the SHA-1 of the upper-case
// service name (UTF-16LE) read as five little-endian 32-bit numbers.
// Deriving it avoids hard-coding a long number that is easy to get wrong.
func ServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	parts := make([]string, 5)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return "S-1-5-80-" + strings.Join(parts, "-")
}