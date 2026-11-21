//go:build linux

package collector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HPK13/proctrace/internal/event"
)

// clockTicks is USER_HZ, which is 100 on every mainstream Linux build.
const clockTicks = 100

// listProcesses reads /proc. Linux support exists so the agent can be
// developed and tested without a Windows machine.
func listProcesses() ([]event.Process, error) {
	boot, err := bootTime()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []event.Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProc(pid, boot)
		if err != nil {
			continue // exited mid-scan or not readable
		}
		procs = append(procs, p)
	}
	return procs, nil
}

func readProc(pid int, boot time.Time) (event.Process, error) {
	dir := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return event.Process{}, err
	}
	// Format: pid (comm) state ppid ... ; comm may contain spaces/parens.
	open, closeIdx := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || closeIdx < open {
		return event.Process{}, fmt.Errorf("malformed stat for %d", pid)
	}
	fields := strings.Fields(string(stat[closeIdx+1:]))
	if len(fields) < 20 {
		return event.Process{}, fmt.Errorf("short stat for %d", pid)
	}
	ppid, _ := strconv.Atoi(fields[1])               // field 4
	ticks, _ := strconv.ParseInt(fields[19], 10, 64) // field 22: starttime

	p := event.Process{
		PID:   pid,
		PPID:  ppid,
		Name:  string(stat[open+1 : closeIdx]),
		Start: boot.Add(time.Duration(ticks) * time.Second / clockTicks).UTC(),
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Executable = strings.TrimSuffix(exe, " (deleted)")
	}
	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.CommandLine = strings.TrimSpace(string(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '})))
	}
	return p, nil
}

func bootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}
