package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf16"
)

// dashes are Unicode characters that Windows programs (PowerShell included)
// accept in place of "-" for parameters, and attackers use to dodge matching.
var dashes = strings.NewReplacer(
	"‐", "-", "‑", "-", "‒", "-", "–", "-", "—", "-",
	"―", "-", "−", "-", "﹣", "-", "－", "-",
)

// quotedConcat matches string concatenation such as "I"+"EX" or 'Down'+'load'.
var quotedConcat = regexp.MustCompile(`["']\s*\+\s*["']`)

// NormalizeCommandLine removes common obfuscation so rules match what the
// command actually does:
//   - Unicode dashes become "-"
//   - "I"+"EX" style concatenation is joined
//   - cmd.exe carets (p^o^w^e^r) and PowerShell backticks (i`e`x) are dropped
//   - quotes are dropped and runs of whitespace collapse to one space
func NormalizeCommandLine(s string) string {
	s = dashes.Replace(s)
	s = quotedConcat.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		switch r {
		case '^', '`', '"', '\'':
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// psEncoded matches -EncodedCommand and every prefix PowerShell accepts for
// it (-e, -en, -enc, … -encodedcommand), plus the -ec alias, followed by the
// Base64 payload.
var psEncoded = regexp.MustCompile(`(?i)(?:^|\s)[-/](?:ec|e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{8,})`)

// maxDecoded caps how much decoded script is kept for matching.
const maxDecoded = 64 << 10

// DecodePowerShell returns the script hidden in a PowerShell -EncodedCommand
// argument (Base64 of UTF-16LE), or "" if there is none.
func DecodePowerShell(cmd string) string {
	m := psEncoded.FindStringSubmatch(dashes.Replace(cmd))
	if m == nil {
		return ""
	}
	payload := strings.TrimRight(m[1], "=")
	raw, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil || len(raw) < 2 {
		return ""
	}
	if len(raw) > 2*maxDecoded {
		raw = raw[:2*maxDecoded]
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u16))
}

// isPowerShell reports whether a process name (or PE original name) is a
// PowerShell host whose -EncodedCommand should be decoded.
func isPowerShell(names ...string) bool {
	for _, n := range names {
		switch n {
		case "powershell.exe", "pwsh.exe", "pwsh.dll", "powershell_ise.exe":
			return true
		}
	}
	return false
}