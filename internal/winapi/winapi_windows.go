//go:build windows

// Package winapi loads Windows system DLLs by their absolute System32 path.
//
// Loading a DLL by bare name lets Windows search the executable's folder and
// the current directory first, so a DLL planted there would run inside an
// elevated agent (DLL search-order hijacking). kernel32.dll is a KnownDLL
// that Windows always maps from System32, so it is safe to use by name to
// find the system directory; everything else goes through SystemDLL.
package winapi

import (
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemDirectoryW = kernel32.NewProc("GetSystemDirectoryW")

	sysDirOnce sync.Once
	sysDir     string
)

// SystemDirectory returns the System32 path, as reported by Windows.
func SystemDirectory() string {
	sysDirOnce.Do(func() {
		buf := make([]uint16, 260)
		n, _, _ := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 || int(n) >= len(buf) {
			sysDir = `C:\Windows\System32`
			return
		}
		sysDir = syscall.UTF16ToString(buf[:n])
	})
	return sysDir
}

// SystemDLL returns a lazily loaded DLL from System32 only.
func SystemDLL(name string) *syscall.LazyDLL {
	return syscall.NewLazyDLL(filepath.Join(SystemDirectory(), name))
}