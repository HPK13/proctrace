package redact

import (
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{`net use \\srv\share P@ssw0rd! /user:corp\admin`, `net use \\srv\share [REDACTED] /user:corp\admin`},
		{`net use Z: \\srv\share * /user:admin`, `net use Z: \\srv\share * /user:admin`},
		{`net user bob Winter2026! /add`, `net user bob [REDACTED] /add`},
		{`curl -H "Authorization: Bearer abcdefghijklmnop" https://api.example`, `curl -H "Authorization: Bearer [REDACTED]" https://api.example`},
		{`mysql -u root -pSecret123 db`, `mysql -u root -p[REDACTED] db`},
		{`sqlcmd -S db -U sa -P Hunter2`, `sqlcmd -S db -U sa -P [REDACTED]`},
		{`psexec \\host -u admin -p S3cret cmd`, `psexec \\host -u admin -p [REDACTED] cmd`},
		{`app.exe --password=hunter2 --verbose`, `app.exe --password=[REDACTED] --verbose`},
		{`app.exe --token abc123`, `app.exe --token [REDACTED]`},
		{`wmic /node:pc /user:a /password:pw123 process list`, `wmic /node:pc /user:a /password:[REDACTED] process list`},
		{`git clone https://bob:ghs_secret@github.com/x/y`, `git clone https://bob:[REDACTED]@github.com/x/y`},
		{`setx DB "Server=x;User=sa;Password=abc;"`, `setx DB "Server=x;User=sa;Password=[REDACTED];"`},
		{`aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE`, `aws configure set aws_access_key_id [REDACTED]`},
		{`powershell ConvertTo-SecureString 'Pa55' -AsPlainText -Force`, `powershell ConvertTo-SecureString [REDACTED] -AsPlainText -Force`},
		// Must stay untouched.
		{`msbuild app.sln /p:Configuration=Release`, `msbuild app.sln /p:Configuration=Release`},
		{`ssh -p 2222 host`, `ssh -p 2222 host`},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`, `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`},
	}
	for _, c := range cases {
		if got := CommandLine(c.in); got != c.want {
			t.Errorf("CommandLine(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("abcdef", 3); got != "abc…[truncated]" {
		t.Fatalf("got %q", got)
	}
	if got := Truncate("abc", 0); got != "abc" {
		t.Fatalf("got %q", got)
	}
	// Never splits a multi-byte character.
	if got := Truncate("aé", 2); !strings.HasPrefix(got, "a…") {
		t.Fatalf("got %q", got)
	}
}