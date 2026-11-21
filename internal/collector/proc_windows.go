//go:build windows

package collector

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"github.com/HPK13/proctrace/internal/event"
)

const (
	processQueryLimitedInformation = 0x1000
	processCommandLineInformation  = 60 // PROCESSINFOCLASS, Windows 8.1+
	statusInfoLengthMismatch       = 0xC0000004
)

var (
	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	modNtdll                       = syscall.NewLazyDLL("ntdll.dll")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
	procNtQueryInformationProcess  = modNtdll.NewProc("NtQueryInformationProcess")
)

// listProcesses walks the Toolhelp32 snapshot, then opens each process with
// the least privilege that still exposes its image path, start time and
// command line. Protected processes (and others' processes when not
// elevated) only yield PID, PPID and name.
func listProcesses() ([]event.Process, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return nil, err
	}

	var procs []event.Process
	for {
		p := event.Process{
			PID:  int(pe.ProcessID),
			PPID: int(pe.ParentProcessID),
			Name: syscall.UTF16ToString(pe.ExeFile[:]),
		}
		fillDetails(&p)
		procs = append(procs, p)

		if err := syscall.Process32Next(snap, &pe); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				break
			}
			return procs, err
		}
	}
	return procs, nil
}

func fillDetails(p *event.Process) {
	if p.PID == 0 {
		return
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(p.PID))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)

	var creation, exit, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user) == nil {
		p.Start = time.Unix(0, creation.Nanoseconds()).UTC()
	}
	p.Executable = imagePath(h)
	p.CommandLine = commandLine(h)
}

func imagePath(h syscall.Handle) string {
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// commandLine uses NtQueryInformationProcess(ProcessCommandLineInformation),
// which returns a UNICODE_STRING whose Buffer points into our own buffer.
func commandLine(h syscall.Handle) string {
	if procNtQueryInformationProcess.Find() != nil {
		return ""
	}
	buf := make([]byte, 4096)
	for attempt := 0; attempt < 2; attempt++ {
		var retLen uint32
		status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processCommandLineInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&retLen)))
		if uint32(status) == statusInfoLengthMismatch && retLen > uint32(len(buf)) && retLen < 1<<20 {
			buf = make([]byte, retLen)
			continue
		}
		if status != 0 {
			return ""
		}
		type unicodeString struct {
			Length        uint16
			MaximumLength uint16
			Buffer        uintptr
		}
		us := (*unicodeString)(unsafe.Pointer(&buf[0]))
		off := int(us.Buffer - uintptr(unsafe.Pointer(&buf[0])))
		n := int(us.Length)
		if off < 0 || n <= 0 || off+n > len(buf) {
			return ""
		}
		u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), n/2)
		return syscall.UTF16ToString(u16)
	}
	return ""
}
