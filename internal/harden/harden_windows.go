//go:build windows

package harden

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/HPK13/proctrace/internal/winapi"
)

var (
	modAdvapi32               = winapi.SystemDLL("advapi32.dll")
	procGetNamedSecurityInfoW = modAdvapi32.NewProc("GetNamedSecurityInfoW")
)

const (
	seFileObject             = 1
	ownerSecurityInformation = 0x1
	daclSecurityInformation  = 0x4
	accessAllowedACEType     = 0
	inheritOnlyACE           = 0x8
	tokenElevation           = 20

	// Rights that let a principal change or replace a file or folder:
	// FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY,
	// FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE,
	// GENERIC_ALL.
	writeMask = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
)

// trusted SIDs: SYSTEM, Administrators, TrustedInstaller.
var trusted = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1975359781-227259940": true,
}

// Elevated reports whether the process runs with an elevated (admin) token.
func Elevated() bool {
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(proc, syscall.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	var elevated, n uint32
	if err := syscall.GetTokenInformation(tok, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &n); err != nil {
		return false
	}
	return elevated != 0
}

// writableByOthers reports how path can be modified by someone other than
// SYSTEM, Administrators or TrustedInstaller: a non-trusted owner (owners
// can always rewrite the ACL) or an allow entry granting write-type rights.
// Deny entries are ignored, so the check errs on the side of reporting.
func writableByOthers(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var owner, dacl, sd unsafe.Pointer
	r, _, _ := procGetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&sd)))
	if r != 0 {
		return "", syscall.Errno(r)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(sd)))

	if owner != nil {
		if s, err := (*syscall.SID)(owner).String(); err == nil && !trusted[s] {
			return "owned by " + account((*syscall.SID)(owner), s), nil
		}
	}
	if dacl == nil {
		return "unprotected (no access control list: anyone can write)", nil
	}

	// ACL header: revision(1) sbz1(1) size(2) aceCount(2) sbz2(2).
	count := *(*uint16)(unsafe.Add(dacl, 4))
	ace := unsafe.Add(dacl, 8)
	for i := 0; i < int(count); i++ {
		// ACE header: type(1) flags(1) size(2); allow ACE: mask(4) then SID.
		typ := *(*byte)(ace)
		flags := *(*byte)(unsafe.Add(ace, 1))
		size := *(*uint16)(unsafe.Add(ace, 2))
		if size < 8 {
			break
		}
		if typ == accessAllowedACEType && flags&inheritOnlyACE == 0 {
			mask := *(*uint32)(unsafe.Add(ace, 4))
			if mask&writeMask != 0 {
				sid := (*syscall.SID)(unsafe.Add(ace, 8))
				if s, err := sid.String(); err == nil && !trusted[s] {
					return "writable by " + account(sid, s), nil
				}
			}
		}
		ace = unsafe.Add(ace, int(size))
	}
	return "", nil
}

func account(sid *syscall.SID, s string) string {
	if name, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return fmt.Sprintf(`%s\%s (%s)`, domain, name, s)
		}
		return fmt.Sprintf("%s (%s)", name, s)
	}
	return s
}