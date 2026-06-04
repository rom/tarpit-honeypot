package artifactscan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Engine holds compiled rules and evaluates them against artifacts.
type Engine struct {
	rules  []Rule
	hashes map[string]string // sha256 -> malware family/label (abuse.ch ThreatFox/MalwareBazaar)
}

// NewEngine returns an engine seeded with the built-in rule set.
func NewEngine() *Engine {
	return &Engine{rules: append([]Rule(nil), builtinRules...)}
}

// LoadHashes loads a known-malware SHA-256 set (abuse.ch MalwareBazaar /
// ThreatFox export, normalized to "sha256[,family[,...]]" per line). A captured
// artifact whose hash is in the set is flagged known malware, with the family
// when present. Returns the number of hashes loaded.
func (e *Engine) LoadHashes(path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if e.hashes == nil {
		e.hashes = map[string]string{}
	}
	added := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hash, family := line, ""
		if i := strings.IndexAny(line, ",\t"); i >= 0 {
			hash = strings.TrimSpace(line[:i])
			family = strings.TrimSpace(line[i+1:])
			if j := strings.IndexAny(family, ",\t"); j >= 0 {
				family = strings.TrimSpace(family[:j]) // keep only the first extra field
			}
		}
		hash = strings.ToLower(hash)
		if len(hash) == 64 { // sha256 hex
			e.hashes[hash] = family
			added++
		}
	}
	return added, sc.Err()
}

// HashCount returns the number of loaded known-malware hashes.
func (e *Engine) HashCount() int {
	if e == nil {
		return 0
	}
	return len(e.hashes)
}

// lookupHash reports whether sha256 is a known-malware hash, and its family.
func (e *Engine) lookupHash(sha256 string) (string, bool) {
	if e == nil || len(e.hashes) == 0 {
		return "", false
	}
	fam, ok := e.hashes[strings.ToLower(sha256)]
	return fam, ok
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
