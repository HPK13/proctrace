// Package redact removes secrets from command lines before they are written
// to disk or sent to a collector.
//
// Command lines routinely carry passwords and tokens (net use, sqlcmd -P,
// curl -H "Authorization: Bearer ..."). An agent that records every command
// line on a machine would otherwise become a password store. Redaction runs
// after detection, so rules still see the full command line.
//
// This is best-effort pattern matching: it reduces exposure but cannot
// guarantee that no secret survives, so event logs must still be protected.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Mask replaces each secret.
const Mask = "[REDACTED]"

type rule struct {
	re   *regexp.Regexp
	repl string
}

// Value patterns: the key or flag is kept so analysts still see what was
// passed, only the value is masked.
var rules = []rule{
	// scheme://user:password@host
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`), "${1}" + Mask + "@"},
	// Authorization headers: Bearer / Basic / token
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + Mask},
	// key=value or key: value
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|passphrase|secret|client_?secret|token|access_?token|refresh_?token|api_?key|apikey|accountkey|sharedaccesskey|sig)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;&"']+)`), "${1}${2}" + Mask},
	// --password value, --token=value, /password:value, cmdkey /pass:value, schtasks /rp value
	{regexp.MustCompile(`(?i)((?:^|\s)(?:--?(?:password|passwd|pass|pwd|pw|token|secret|api-?key|client-?secret)|/(?:password|pass|rp))(?:\s+|[=:]))("[^"]*"|'[^']*'|\S+)`), "${1}" + Mask},
	// PowerShell: ConvertTo-SecureString 'plaintext' -AsPlainText
	{regexp.MustCompile(`(?i)(convertto-securestring\s+(?:-string\s+)?)("[^"]*"|'[^']*'|\S+)`), "${1}" + Mask},
}

// Whole-token patterns for well-known credential formats.
var tokens = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),                                                    // AWS access key ID
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                                   // GitHub token
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),                                                 // GitHub fine-grained token
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                                                   // Slack token
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                                                        // Google API key
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),                     // JWT
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), // PEM key
}

// CommandLine returns cmd with secrets masked.
func CommandLine(cmd string) string {
	if cmd == "" {
		return cmd
	}
	cmd = positional(cmd)
	for _, r := range rules {
		cmd = r.re.ReplaceAllString(cmd, r.repl)
	}
	for _, re := range tokens {
		cmd = re.ReplaceAllString(cmd, Mask)
	}
	return cmd
}

// positional handles tools that take a password as a plain argument or a
// short flag, where a generic pattern would hit too many unrelated
// commands (for example msbuild's /p:Property=Value).
func positional(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return cmd
	}
	tool := strings.ToLower(strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(strings.Trim(fields[0], `"`), `\`, "/"))), ".exe"))
	changed := false
	mask := func(i int) {
		if i < len(fields) && fields[i] != "*" {
			fields[i] = Mask
			changed = true
		}
	}

	switch tool {
	case "psexec", "psexec64", "paexec":
		for i := 1; i < len(fields); i++ {
			if strings.EqualFold(fields[i], "-p") {
				mask(i + 1)
			}
		}
	case "sqlcmd", "osql", "bcp", "isql":
		for i := 1; i < len(fields); i++ {
			switch f := fields[i]; {
			case f == "-P" || f == "/P":
				mask(i + 1)
			case strings.HasPrefix(f, "-P") && len(f) > 2:
				fields[i], changed = "-P"+Mask, true
			}
		}
	case "mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump":
		for i := 1; i < len(fields); i++ {
			if f := fields[i]; strings.HasPrefix(f, "-p") && len(f) > 2 {
				fields[i], changed = "-p"+Mask, true
			}
		}
	case "schtasks":
		for i := 1; i < len(fields); i++ {
			if strings.EqualFold(fields[i], "/p") {
				mask(i + 1)
			}
		}
	case "net", "net1":
		if len(fields) < 3 {
			break
		}
		switch strings.ToLower(fields[1]) {
		case "use":
			// net use [drive:] \\server\share [password | *] [/user:...]
			for i := 2; i < len(fields); i++ {
				f := fields[i]
				if strings.HasPrefix(f, "/") || strings.HasPrefix(f, `\\`) || f == "*" ||
					(len(f) == 2 && f[1] == ':') {
					continue
				}
				mask(i)
			}
		case "user":
			// net user <name> <password> [/add ...]
			args := 0
			for i := 2; i < len(fields); i++ {
				if strings.HasPrefix(fields[i], "/") {
					continue
				}
				if args++; args == 2 {
					mask(i)
				}
			}
		}
	}
	if !changed {
		return cmd
	}
	return strings.Join(fields, " ")
}

// Truncate shortens s to at most max bytes (0 = no limit), on a UTF-8
// boundary, marking that it was cut.
func Truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…[truncated]"
}