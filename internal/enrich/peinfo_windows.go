//go:build windows

package enrich

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/HPK13/proctrace/internal/winapi"
)

var (
	modVersion                  = winapi.SystemDLL("version.dll")
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

// originalFileName reads OriginalFilename from the file's version resource.
// Pointers returned by VerQueryValueW point into buf, so they are turned
// into offsets and bounds-checked rather than dereferenced directly.
func originalFileName(path string) string {
	if modVersion.Load() != nil {
		return ""
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	size, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(p)), 0)
	if size == 0 || size > 4<<20 {
		return ""
	}
	buf := make([]byte, size)
	base := uintptr(unsafe.Pointer(&buf[0]))
	if r, _, _ := procGetFileVersionInfoW.Call(uintptr(unsafe.Pointer(p)), 0, size, base); r == 0 {
		return ""
	}

	query := func(sub string) (off, n int, ok bool) {
		s, err := syscall.UTF16PtrFromString(sub)
		if err != nil {
			return 0, 0, false
		}
		var val unsafe.Pointer
		var length uint32
		r, _, _ := procVerQueryValueW.Call(base, uintptr(unsafe.Pointer(s)),
			uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&length)))
		if r == 0 || val == nil {
			return 0, 0, false
		}
		off = int(uintptr(val) - base)
		if off < 0 || off >= len(buf) {
			return 0, 0, false
		}
		return off, int(length), true
	}

	// Language/code-page pairs from the Translation table, then common fallbacks.
	var codes []string
	if off, n, ok := query(`\VarFileInfo\Translation`); ok {
		for i := 0; i+4 <= n && off+i+4 <= len(buf) && i < 64; i += 4 {
			lang := binary.LittleEndian.Uint16(buf[off+i:])
			cp := binary.LittleEndian.Uint16(buf[off+i+2:])
			codes = append(codes, fmt.Sprintf("%04x%04x", lang, cp))
		}
	}
	codes = append(codes, "040904b0", "040904e4", "000004b0")

	for _, code := range codes {
		off, n, ok := query(`\StringFileInfo\` + code + `\OriginalFilename`)
		if !ok || n <= 0 {
			continue
		}
		end := off + 2*n // n is in UTF-16 code units
		if end > len(buf) {
			end = len(buf) &^ 1
		}
		u16 := make([]uint16, 0, n)
		for i := off; i+1 < end; i += 2 {
			u16 = append(u16, binary.LittleEndian.Uint16(buf[i:]))
		}
		if name := syscall.UTF16ToString(u16); name != "" {
			return name
		}
	}
	return ""
}