package harden

import "testing"

func TestServiceSID(t *testing.T) {
	// Value reported by Windows 11 for NT SERVICE\TrustedInstaller.
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, name := range []string{"TrustedInstaller", "trustedinstaller"} {
		if got := ServiceSID(name); got != want {
			t.Errorf("ServiceSID(%q) = %s, want %s", name, got, want)
		}
	}
}