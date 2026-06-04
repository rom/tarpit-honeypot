package artifactscan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Engine holds compiled rules and evaluates them against artifacts.
type Engine struct {
	rules []Rule
}

// NewEngine returns an engine seeded with the built-in rule set.
func NewEngine() *Engine {
	return &Engine{rules: append([]Rule(nil), builtinRules...)}
}

// LoadDir compiles every .yar / .yara file under path (a file or directory)
// and adds the rules to the engine. Returns the number of rules added and any
// per-rule / per-file parse errors (non-fatal: the engine keeps what compiled).
func (e *Engine) LoadDir(path string) (int, []error) {
	if path == "" {
		return 0, nil
	}
	var files []string
	info, err := os.Stat(path)
	if err != nil {
		return 0, []error{err}
	}
	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ext := strings.ToLower(filepath.Ext(p)); ext == ".yar" || ext == ".yara" {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = []string{path}
	}
	added := 0
	var errs []error
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules, perrs := ParseRules(string(src))
		for _, pe := range perrs {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(f), pe))
		}
		e.rules = append(e.rules, rules...)
		added += len(rules)
	}
	return added, errs
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Scan evaluates every rule against data and returns the firing matches,
// sorted by rule name.
func (e *Engine) Scan(data []byte) []Match {
	if e == nil || len(e.rules) == 0 || len(data) == 0 {
		return nil
	}
	lower := bytes.ToLower(data)
	var out []Match
	for i := range e.rules {
		if m, ok := e.rules[i].eval(data, lower); ok {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}
