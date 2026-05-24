package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// SeverityOverride re-maps the reported severity of matching events. An
// operator who knows an event is worse (or less worse) in their environment
// than the built-in default can pin the level it is reported at. The override
// is applied in the router (the single dispatch chokepoint), so it affects
// routing, min-severity gating, the local store, and every sink — and the
// event is marked as a local override (logs, event meta, web UI) so the change
// is never silent.
//
//	severity_overrides:
//	  - rule: correlate:port_scan   # exact rule_id
//	    severity: medium
//	  - rule: "cve:*"               # prefix wildcard (trailing *)
//	    severity: critical
type SeverityOverride struct {
	// Rule matches an event's rule_id. Either an exact id
	// ("correlate:port_scan", "listener:ssh-bait", "cve:CVE-2021-44228") or a
	// trailing-* prefix ("cve:*", "correlate:*", "attack:*").
	Rule string `yaml:"rule"`
	// Severity is the level matching events are reported at: low / medium /
	// high / critical.
	Severity string `yaml:"severity"`
}

// SeverityOverrideSet is the compiled matcher: exact ids win over prefixes,
// and among prefixes the longest (most specific) wins.
type SeverityOverrideSet struct {
	exact    map[string]ovrEntry
	prefixes []ovrEntry // sorted longest-prefix-first
}

type ovrEntry struct {
	match string // the configured rule pattern (for reporting)
	key   string // exact id, or the prefix (rule minus trailing *)
	sev   event.Severity
}

// CompileSeverityOverrides validates and compiles the override list.
func CompileSeverityOverrides(list []SeverityOverride) (*SeverityOverrideSet, error) {
	s := &SeverityOverrideSet{exact: map[string]ovrEntry{}}
	for _, o := range list {
		if strings.TrimSpace(o.Rule) == "" {
			return nil, fmt.Errorf("severity_overrides: empty rule")
		}
		sev, err := event.ParseSeverity(o.Severity)
		if err != nil {
			return nil, fmt.Errorf("severity_overrides: rule %q: %w", o.Rule, err)
		}
		if strings.HasSuffix(o.Rule, "*") {
			s.prefixes = append(s.prefixes, ovrEntry{match: o.Rule, key: strings.TrimSuffix(o.Rule, "*"), sev: sev})
		} else {
			s.exact[o.Rule] = ovrEntry{match: o.Rule, key: o.Rule, sev: sev}
		}
	}
	sort.Slice(s.prefixes, func(i, j int) bool { return len(s.prefixes[i].key) > len(s.prefixes[j].key) })
	return s, nil
}

// Apply returns the overridden severity and the matching rule pattern for
// ruleID, or ok=false if no override applies.
func (s *SeverityOverrideSet) Apply(ruleID string) (sev event.Severity, match string, ok bool) {
	if s == nil {
		return 0, "", false
	}
	if e, found := s.exact[ruleID]; found {
		return e.sev, e.match, true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(ruleID, p.key) {
			return p.sev, p.match, true
		}
	}
	return 0, "", false
}

// Len reports how many override rules are compiled.
func (s *SeverityOverrideSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.exact) + len(s.prefixes)
}

// Empty reports whether no overrides are configured.
func (s *SeverityOverrideSet) Empty() bool { return s.Len() == 0 }
