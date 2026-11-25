//go:build !windows

package harden

import (
	"fmt"
	"os"
	"syscall"
)

// Elevated reports whether the process runs as root.
func Elevated() bool { return os.Geteuid() == 0 }

// writableByOthers reports whether path is owned by a non-root user or is
// writable by group or others.
func writableByOthers(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Sprintf("owned by uid %d", st.Uid), nil
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("writable by group or others (mode %v)", fi.Mode().Perm()), nil
	}
	return "", nil
}
