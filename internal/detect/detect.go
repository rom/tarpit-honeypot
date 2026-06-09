// Package detect is a small, declarative "detection-as-code" layer: operators
// drop Sigma-inspired YAML rules in a directory and the sensor matches them
// against every event in-flight, with no recompile. A match adds the rule's
// tags as anomaly markers (so they flow into routing / search / exports /
// ATT&CK chips just like built-in markers) and may *raise* the event severity.
//
// This is deliberately a conservative, non-Turing-complete matcher — field
// equality / contains / prefix / suffix / regex / numeric / exists, ANDed
// across fields with OR within a field's value list. It never executes
// anything; the sandboxed `lua` response handler remains the only scripting
// surface.
package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// maxRules bounds how many rules an Engine will load (a guard against a runaway
// rules directory). Matching is O(rules × conditions) per event.
const maxRules = 2000

// Rule is one detection rule as authored in YAML.
type Rule struct {
	ID          string         `yaml:"id"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description,omitempty"`
	Severity    string         `yaml:"severity,omitempty"` // only ever RAISES the event severity
	Tags        []string       `yaml:"tags,omitempty"`     // added to the event as anomaly markers
	Match       map[string]any `yaml:"match"`              // field[|mod] -> value | [values] (AND across keys)

	conds  []condition // compiled from Match
	sev    event.Severity
	hasSev bool
}

// condition is one compiled "field|modifier -> values" test.
type condition struct {
	field  string
	mod    string
	values []string
	res    []*regexp.Regexp // compiled regexes for mod == "re"
}

// Engine holds the compiled rule set. The zero value (or a nil *Engine) is a
// no-op, so callers can hold one unconditionally.
type Engine struct {
	rules []Rule
}

// Rules returns how many rules are loaded (for validate-config / logging).
func (e *Engine) Count() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Load reads every *.yml / *.yaml file in dir (non-recursive) and compiles the
// rules. An empty dir (or "") yields an empty, no-op Engine. Returns the engine
// plus a slice of per-file errors so a single bad rule file doesn't abort the
// whole load (the sensor logs them and runs the rest).
func Load(dir string) (*Engine, []error) {
	e := &Engine{}
	if dir == "" {
		return e, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return e, nil
		}
		return e, []error{err}
	}
	var errs []error
	names := make([]string, 0, len(entries))
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		n := en.Name()
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			names = append(names, n)
		}
	}
	sort.Strings(names) // deterministic load order
	for _, n := range names {
		path := filepath.Join(dir, n)
		rules, err := parseFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		for _, r := range rules {
			if len(e.rules) >= maxRules {
				errs = append(errs, fmt.Errorf("rule cap %d reached; ignoring the rest", maxRules))
				return e, errs
			}
			if err := r.compile(); err != nil {
				errs = append(errs, fmt.Errorf("%s: rule %q: %w", n, r.ID, err))
				continue
			}
			e.rules = append(e.rules, r)
		}
	}
	return e, errs
}

// parseFile accepts either a top-level YAML list of rules or a document with a
// `rules:` key, so operators can keep one or many rules per file.
func parseFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []Rule
	if err := yaml.Unmarshal(b, &list); err == nil && len(list) > 0 {
		return list, nil
	}
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Rules, nil
}

func (r *Rule) compile() error {
	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("missing/empty match")
	}
	if r.Severity != "" {
		sev, err := event.ParseSeverity(r.Severity)
		if err != nil {
			return fmt.Errorf("severity: %w", err)
		}
		r.sev, r.hasSev = sev, true
	}
	keys := make([]string, 0, len(r.Match))
	for k := range r.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable evaluation order
	for _, key := range keys {
		field, mod := key, ""
		if i := strings.IndexByte(key, '|'); i >= 0 {
			field, mod = key[:i], key[i+1:]
		}
		c := condition{field: strings.ToLower(field), mod: strings.ToLower(mod)}
		for _, v := range toStrings(r.Match[key]) {
			c.values = append(c.values, v)
			if c.mod == "re" {
				re, err := regexp.Compile(v)
				if err != nil {
					return fmt.Errorf("field %q regex %q: %w", field, v, err)
				}
				c.res = append(c.res, re)
			}
		}
		switch c.mod {
		case "", "contains", "prefix", "suffix", "re", "gt", "lt", "exists":
		default:
			return fmt.Errorf("field %q: unknown modifier %q", field, mod)
		}
		r.conds = append(r.conds, c)
	}
	return nil
}

// Apply tests every rule against ev. For each match it adds the rule's tags +
// a detect:<id> marker as anomalies, records the id under meta.detect_rules,
// and raises the severity if the rule asks for a higher one. Returns the ids
// that matched. Safe on a nil Engine / nil event.
func (e *Engine) Apply(ev *event.Event) []string {
	if e == nil || ev == nil || len(e.rules) == 0 {
		return nil
	}
	var matched []string
	for i := range e.rules {
		r := &e.rules[i]
		if r.matches(ev) {
			matched = append(matched, r.ID)
			addAnomaly(ev, "detect:"+r.ID)
			for _, t := range r.Tags {
				addAnomaly(ev, t)
			}
			if r.hasSev && r.sev > ev.Severity {
				ev.Severity = r.sev
				ev.SeverityOverridden = true
			}
		}
	}
	if len(matched) > 0 {
		if ev.Meta == nil {
			ev.Meta = map[string]any{}
		}
		ev.Meta["detect_rules"] = matched
	}
	return matched
}

func (r *Rule) matches(ev *event.Event) bool {
	for ci := range r.conds {
		if !r.conds[ci].eval(ev) {
			return false // AND across conditions
		}
	}
	return true
}

func (c *condition) eval(ev *event.Event) bool {
	cands := resolveField(ev, c.field)
	if c.mod == "exists" {
		for _, s := range cands {
			if s != "" {
				return true
			}
		}
		return false
	}
	for _, cand := range cands {
		lc := strings.ToLower(cand)
		for vi, v := range c.values {
			lv := strings.ToLower(v)
			switch c.mod {
			case "":
				if lc == lv {
					return true
				}
			case "contains":
				if strings.Contains(lc, lv) {
					return true
				}
			case "prefix":
				if strings.HasPrefix(lc, lv) {
					return true
				}
			case "suffix":
				if strings.HasSuffix(lc, lv) {
					return true
				}
			case "re":
				if vi < len(c.res) && c.res[vi].MatchString(cand) {
					return true
				}
			case "gt", "lt":
				cn, e1 := strconv.ParseFloat(strings.TrimSpace(cand), 64)
				vn, e2 := strconv.ParseFloat(strings.TrimSpace(v), 64)
				if e1 == nil && e2 == nil && ((c.mod == "gt" && cn > vn) || (c.mod == "lt" && cn < vn)) {
					return true
				}
			}
		}
	}
	return false
}

// resolveField returns the candidate string values for a rule field on an
// event. meta.* walks the (possibly nested) Meta map by dotted path.
func resolveField(ev *event.Event, field string) []string {
	switch field {
	case "handler":
		return []string{ev.Handler}
	case "rule_id", "rule":
		return []string{ev.RuleID}
	case "proto":
		return []string{ev.Proto}
	case "severity":
		return []string{ev.Severity.String()}
	case "source_ip", "src_ip", "source":
		return []string{ev.Source.IP}
	case "dest_ip", "dst_ip", "dest":
		return []string{ev.Dest.IP}
	case "dest_port", "dst_port", "port":
		return []string{strconv.Itoa(ev.Dest.Port)}
	case "banner":
		return []string{ev.BannerSent}
	case "sensor":
		return []string{ev.Sensor}
	case "anomaly", "anomalies":
		return ev.Anomalies
	case "mitre", "technique", "techniques":
		return ev.MitreTechniques
	case "tactic", "tactics":
		return ev.MitreTactics
	}
	if rest, ok := strings.CutPrefix(field, "meta."); ok {
		return metaPath(ev.Meta, strings.Split(rest, "."))
	}
	return nil
}

// metaPath walks a dotted path into a meta map, stringifying the leaf (and each
// element when the leaf is a slice).
func metaPath(m map[string]any, path []string) []string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = mm[p]
		if !ok {
			return nil
		}
	}
	return toStrings(cur)
}

// toStrings flattens a YAML/meta value (scalar or list) into strings.
func toStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, toStrings(e)...)
		}
		return out
	case bool:
		return []string{strconv.FormatBool(t)}
	case int:
		return []string{strconv.Itoa(t)}
	case int64:
		return []string{strconv.FormatInt(t, 10)}
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	default:
		return []string{fmt.Sprintf("%v", t)}
	}
}

func addAnomaly(ev *event.Event, marker string) {
	for _, a := range ev.Anomalies {
		if a == marker {
			return
		}
	}
	ev.Anomalies = append(ev.Anomalies, marker)
}
