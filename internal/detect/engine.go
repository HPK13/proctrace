// Package detect evaluates processes against JSON rules.
//
// A rule matches when every condition it sets holds. Within a list
// condition, any one entry is enough. String comparisons are
// case-insensitive. Conditions about the parent only fire when the parent
// was verified by lineage.Link, so a PID-reuse mix-up cannot raise an alert.
//
// Inputs are hardened against simple evasion before matching:
//   - "name" matches the process name OR its PE OriginalFileName, so a
//     renamed powershell.exe is still recognised.
//   - command_line_regex runs on a normalised command line (see
//     NormalizeCommandLine) and on the decoded payload of PowerShell
//     -EncodedCommand.
//
// A rule may carry an "except" block with the same conditions; when the
// except block matches, the rule does not fire.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/lineage"
)

// Match holds a set of conditions. Empty fields are ignored.
type Match struct {
	Name             []string `json:"name,omitempty"`
	NameNot          []string `json:"name_not,omitempty"`
	RenamedFrom      []string `json:"renamed_from,omitempty"`
	ParentName       []string `json:"parent_name,omitempty"`
	ParentNameNot    []string `json:"parent_name_not,omitempty"`
	PathPrefix       []string `json:"path_prefix,omitempty"`
	PathPrefixNot    []string `json:"path_prefix_not,omitempty"`
	PathContains     []string `json:"path_contains,omitempty"`
	CommandLineRegex []string `json:"command_line_regex,omitempty"`
	NameLookalike    []string `json:"name_lookalike,omitempty"`
	NameNonASCII     bool     `json:"name_non_ascii,omitempty"`
	ParentStatus     []string `json:"parent_status,omitempty"`
}

// Rule is one detection.
type Rule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Score       int      `json:"score"`
	Attack      []string `json:"attack,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Match       Match    `json:"match"`
	Except      *Match   `json:"except,omitempty"`
}

// RuleFile is the on-disk format.
type RuleFile struct {
	Rules []Rule `json:"rules"`
}

type compiledMatch struct {
	Match
	cmd []*regexp.Regexp
}

type compiled struct {
	Rule
	match  compiledMatch
	except *compiledMatch
}

// Engine evaluates compiled rules.
type Engine struct {
	rules []compiled

	// Source and SHA256 identify the rule set, for logging at start-up so a
	// tampered rule file shows up in the agent's own log.
	Source string
	SHA256 string
}

// LoadFile reads and compiles a rule file.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data, path)
}

// Load compiles rules from JSON; source names where they came from.
func Load(data []byte, source string) (*Engine, error) {
	var rf RuleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	e, err := New(rf.Rules)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	sum := sha256.Sum256(data)
	e.Source, e.SHA256 = source, hex.EncodeToString(sum[:])
	return e, nil
}

func compileMatch(m Match, id string) (compiledMatch, error) {
	c := compiledMatch{Match: m}
	for _, expr := range m.CommandLineRegex {
		re, err := regexp.Compile("(?i)" + expr)
		if err != nil {
			return c, fmt.Errorf("rule %s: %w", id, err)
		}
		c.cmd = append(c.cmd, re)
	}
	return c, nil
}

// New compiles rules, rejecting duplicates and bad regexes.
func New(rules []Rule) (*Engine, error) {
	e := &Engine{}
	ids := map[string]bool{}
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.ID == "" {
			return nil, fmt.Errorf("rule %q has no id", r.Title)
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %s", r.ID)
		}
		ids[r.ID] = true
		c := compiled{Rule: r}
		var err error
		if c.match, err = compileMatch(r.Match, r.ID); err != nil {
			return nil, err
		}
		if r.Except != nil {
			ex, err := compileMatch(*r.Except, r.ID)
			if err != nil {
				return nil, err
			}
			c.except = &ex
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Len reports how many rules are active.
func (e *Engine) Len() int { return len(e.rules) }

// subject is a process prepared for matching (computed once per process).
type subject struct {
	p           event.Process
	name        string // lower-case process name
	original    string // lower-case PE OriginalFileName without ".mui", or ""
	path        string // lower-case executable path
	parent      string // lower-case parent name if verified
	parentKnown bool
	cmd         string // normalised command line
	decoded     string // normalised -EncodedCommand payload, or ""
}

func newSubject(p event.Process) subject {
	s := subject{
		p:    p,
		name: strings.ToLower(p.Name),
		path: normPath(p.Executable),
		cmd:  NormalizeCommandLine(p.CommandLine),
	}
	if p.PE != nil {
		s.original = normOriginal(p.PE.OriginalFileName)
	}
	if p.ParentStatus == lineage.StatusVerified && p.Parent != nil {
		s.parentKnown = true
		s.parent = strings.ToLower(p.Parent.Name)
	}
	if isPowerShell(s.name, s.original) {
		s.decoded = NormalizeCommandLine(DecodePowerShell(p.CommandLine))
	}
	return s
}

// Evaluate returns matching detections (highest score first) and a 0-100
// risk score: the top score plus 5 for each additional detection.
func (e *Engine) Evaluate(p event.Process) ([]event.Detection, int) {
	s := newSubject(p)
	var dets []event.Detection
	for _, r := range e.rules {
		reason, ok := r.match.eval(s)
		if !ok {
			continue
		}
		if r.except != nil {
			if _, skip := r.except.eval(s); skip {
				continue
			}
		}
		dets = append(dets, event.Detection{
			RuleID: r.ID, Title: r.Title, Severity: r.Severity,
			Score: r.Score, Attack: r.Attack, Reason: reason,
		})
	}
	if len(dets) == 0 {
		return nil, 0
	}
	sort.SliceStable(dets, func(i, j int) bool { return dets[i].Score > dets[j].Score })
	score := min(dets[0].Score+5*(len(dets)-1), 100)
	return dets, score
}

// eval reports whether every set condition holds, and why.
func (m compiledMatch) eval(s subject) (string, bool) {
	var why []string

	if len(m.Name) > 0 {
		switch {
		case inFold(s.name, m.Name):
			why = append(why, "process "+s.p.Name)
		case s.original != "" && inFold(s.original, m.Name):
			why = append(why, fmt.Sprintf("process %s (originally %s)", s.p.Name, s.original))
		default:
			return "", false
		}
	}
	if len(m.NameNot) > 0 && inFold(s.name, m.NameNot) {
		return "", false
	}
	if len(m.RenamedFrom) > 0 {
		if s.original == "" || s.original == s.name || !inFold(s.original, m.RenamedFrom) {
			return "", false
		}
		why = append(why, fmt.Sprintf("renamed copy of %s running as %s", s.original, s.p.Name))
	}
	if len(m.ParentName) > 0 {
		if !s.parentKnown || !inFold(s.parent, m.ParentName) {
			return "", false
		}
		why = append(why, "parent "+s.p.Parent.Name)
	}
	if len(m.ParentNameNot) > 0 {
		if !s.parentKnown || inFold(s.parent, m.ParentNameNot) {
			return "", false
		}
		why = append(why, fmt.Sprintf("unexpected parent %s (expected %s)", s.p.Parent.Name, strings.Join(m.ParentNameNot, " or ")))
	}
	if len(m.PathPrefix) > 0 {
		if s.path == "" || !hasAnyPrefix(s.path, m.PathPrefix) {
			return "", false
		}
		why = append(why, "running from "+s.p.Executable)
	}
	if len(m.PathPrefixNot) > 0 {
		if s.path == "" || hasAnyPrefix(s.path, m.PathPrefixNot) {
			return "", false
		}
		why = append(why, "running from "+s.p.Executable)
	}
	if len(m.PathContains) > 0 {
		hit := ""
		for _, v := range m.PathContains {
			if s.path != "" && strings.Contains(s.path, strings.ToLower(v)) {
				hit = v
				break
			}
		}
		if hit == "" {
			return "", false
		}
		why = append(why, "path contains "+hit)
	}
	if len(m.cmd) > 0 {
		hit := ""
		for _, re := range m.cmd {
			pattern := strings.TrimPrefix(re.String(), "(?i)")
			if s.cmd != "" && re.MatchString(s.cmd) {
				hit = "command line matches " + pattern
				break
			}
			if s.decoded != "" && re.MatchString(s.decoded) {
				hit = "decoded -EncodedCommand payload matches " + pattern
				break
			}
		}
		if hit == "" {
			return "", false
		}
		why = append(why, hit)
	}
	if len(m.NameLookalike) > 0 {
		target := lookalike(s.name, m.NameLookalike)
		if target == "" {
			return "", false
		}
		why = append(why, fmt.Sprintf("name %q resembles %s", s.p.Name, target))
	}
	if m.NameNonASCII {
		if !hasNonASCII(s.p.Name) {
			return "", false
		}
		why = append(why, fmt.Sprintf("name %q contains non-ASCII characters", s.p.Name))
	}
	if len(m.ParentStatus) > 0 {
		if !inFold(s.p.ParentStatus, m.ParentStatus) {
			return "", false
		}
		why = append(why, "parent status "+s.p.ParentStatus)
	}
	if len(why) == 0 { // a block with no conditions never matches
		return "", false
	}
	return strings.Join(why, "; "), true
}

func normPath(p string) string {
	p = strings.TrimPrefix(p, `\\?\`)
	return strings.ToLower(p)
}

// normOriginal lower-cases an OriginalFileName and strips the ".mui" that
// some Windows binaries carry (powershell.exe reports "PowerShell.EXE.MUI").
func normOriginal(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".mui")
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(s, strings.ToLower(pre)) {
			return true
		}
	}
	return false
}

func inFold(s string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// lookalike returns the protected name that name imitates, if any: a
// different name within edit distance 1 (2 for names of 9+ characters).
func lookalike(name string, protected []string) string {
	for _, t := range protected {
		if name == strings.ToLower(t) {
			return ""
		}
	}
	for _, t := range protected {
		t = strings.ToLower(t)
		limit := 1
		if len(t) >= 9 {
			limit = 2
		}
		if d := levenshtein(name, t); d > 0 && d <= limit {
			return t
		}
	}
	return ""
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}