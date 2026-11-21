// Package detect evaluates processes against JSON rules.
//
// A rule matches when every condition it sets holds. Within a list
// condition, any one entry is enough. String comparisons are
// case-insensitive. Conditions about the parent only fire when the parent
// was verified by lineage.Link, so a PID-reuse mix-up cannot raise an alert.
package detect

import (
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

// Match holds a rule's conditions. Empty fields are ignored.
type Match struct {
	Name             []string `json:"name,omitempty"`
	NameNot          []string `json:"name_not,omitempty"`
	ParentName       []string `json:"parent_name,omitempty"`
	ParentNameNot    []string `json:"parent_name_not,omitempty"`
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
}

// RuleFile is the on-disk format.
type RuleFile struct {
	Rules []Rule `json:"rules"`
}

type compiled struct {
	Rule
	cmd []*regexp.Regexp
}

// Engine evaluates compiled rules.
type Engine struct {
	rules []compiled
}

// LoadFile reads and compiles a rule file.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf RuleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return New(rf.Rules)
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
		for _, expr := range r.Match.CommandLineRegex {
			re, err := regexp.Compile("(?i)" + expr)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			c.cmd = append(c.cmd, re)
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Len reports how many rules are active.
func (e *Engine) Len() int { return len(e.rules) }

// Evaluate returns matching detections (highest score first) and a 0-100
// risk score: the top score plus 5 for each additional detection.
func (e *Engine) Evaluate(p event.Process) ([]event.Detection, int) {
	var dets []event.Detection
	for _, r := range e.rules {
		if reason, ok := r.matches(p); ok {
			dets = append(dets, event.Detection{
				RuleID: r.ID, Title: r.Title, Severity: r.Severity,
				Score: r.Score, Attack: r.Attack, Reason: reason,
			})
		}
	}
	if len(dets) == 0 {
		return nil, 0
	}
	sort.SliceStable(dets, func(i, j int) bool { return dets[i].Score > dets[j].Score })
	score := min(dets[0].Score+5*(len(dets)-1), 100)
	return dets, score
}

func (r compiled) matches(p event.Process) (string, bool) {
	m := r.Match
	name := strings.ToLower(p.Name)
	path := normPath(p.Executable)
	parentKnown := p.ParentStatus == lineage.StatusVerified && p.Parent != nil
	parent := ""
	if parentKnown {
		parent = strings.ToLower(p.Parent.Name)
	}
	var why []string

	if len(m.Name) > 0 {
		if !inFold(name, m.Name) {
			return "", false
		}
		why = append(why, "process "+p.Name)
	}
	if len(m.NameNot) > 0 && inFold(name, m.NameNot) {
		return "", false
	}
	if len(m.ParentName) > 0 {
		if !parentKnown || !inFold(parent, m.ParentName) {
			return "", false
		}
		why = append(why, "parent "+p.Parent.Name)
	}
	if len(m.ParentNameNot) > 0 {
		if !parentKnown || inFold(parent, m.ParentNameNot) {
			return "", false
		}
		why = append(why, fmt.Sprintf("unexpected parent %s (expected %s)", p.Parent.Name, strings.Join(m.ParentNameNot, " or ")))
	}
	if len(m.PathPrefixNot) > 0 {
		if path == "" {
			return "", false
		}
		for _, pre := range m.PathPrefixNot {
			if strings.HasPrefix(path, strings.ToLower(pre)) {
				return "", false
			}
		}
		why = append(why, "running from "+p.Executable)
	}
	if len(m.PathContains) > 0 {
		hit := ""
		for _, s := range m.PathContains {
			if path != "" && strings.Contains(path, strings.ToLower(s)) {
				hit = s
				break
			}
		}
		if hit == "" {
			return "", false
		}
		why = append(why, "path contains "+hit)
	}
	if len(r.cmd) > 0 {
		hit := ""
		for _, re := range r.cmd {
			if p.CommandLine != "" && re.MatchString(p.CommandLine) {
				hit = re.String()[4:] // drop "(?i)"
				break
			}
		}
		if hit == "" {
			return "", false
		}
		why = append(why, "command line matches "+hit)
	}
	if len(m.NameLookalike) > 0 {
		target := lookalike(name, m.NameLookalike)
		if target == "" {
			return "", false
		}
		why = append(why, fmt.Sprintf("name %q resembles %s", p.Name, target))
	}
	if m.NameNonASCII {
		if !hasNonASCII(p.Name) {
			return "", false
		}
		why = append(why, fmt.Sprintf("name %q contains non-ASCII characters", p.Name))
	}
	if len(m.ParentStatus) > 0 {
		if !inFold(p.ParentStatus, m.ParentStatus) {
			return "", false
		}
		why = append(why, "parent status "+p.ParentStatus)
	}
	if len(why) == 0 { // a rule with no conditions never matches
		return "", false
	}
	return strings.Join(why, "; "), true
}

func normPath(p string) string {
	p = strings.TrimPrefix(p, `\\?\`)
	return strings.ToLower(p)
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
		t = strings.ToLower(t)
		if name == t {
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
