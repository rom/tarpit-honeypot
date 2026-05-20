// Override + include layering for config loading.
//
// LoadWithOverrides drives a 4-step pipeline:
//
//  1. Read the base YAML file into a generic map.
//  2. If a sibling conf.d/ directory exists, merge every *.yaml /
//     *.yml file in lexical order over the base (later wins).
//  3. Apply environment-variable overrides — anything matching
//     TARPIT_<KEY_PATH> (uppercase, dots and dashes -> underscores)
//     gets injected into the map.
//  4. Apply --set key.path=value overrides.
//
// Then the merged map is re-marshalled and decoded into the Config
// struct so applyDefaults() + Validate() see the final shape.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadWithOverrides loads `path`, layers any sibling conf.d/*.yaml, then
// applies environment-variable overrides and the CLI `--set` slice.
func LoadWithOverrides(path string, sets []string) (*Config, error) {
	base, err := readBaseWithConfd(path)
	if err != nil {
		return nil, err
	}
	return finalizeConfig(base, sets)
}

// LoadManyWithOverrides loads several base config files and COMBINES them:
// top-level lists (listeners, honeynets, channels, ...) are appended so a
// host defined in any file is used, and maps are deep-merged (later file
// wins for scalar leaves). Each file's own sibling conf.d/ is applied to
// that file first (conf.d keeps its replace-lists semantics — it overrides
// one config; multiple -c files combine). Env + --set apply last. With a
// single path it is identical to LoadWithOverrides.
func LoadManyWithOverrides(paths []string, sets []string) (*Config, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no config path provided")
	}
	if len(paths) == 1 {
		return LoadWithOverrides(paths[0], sets)
	}
	var combined map[string]any
	for _, p := range paths {
		m, err := readBaseWithConfd(p)
		if err != nil {
			return nil, err
		}
		if combined == nil {
			combined = m
		} else {
			combined = combineMaps(combined, m)
		}
	}
	return finalizeConfig(combined, sets)
}

// readBaseWithConfd reads one base file and deep-merges any sibling
// conf.d/*.yaml over it (lexical order, later wins, lists replaced).
func readBaseWithConfd(path string) (map[string]any, error) {
	base, err := readYAMLMap(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(filepath.Dir(path), "conf.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return base, nil // no conf.d sibling
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		extra, err := readYAMLMap(filepath.Join(dir, n))
		if err != nil {
			return nil, fmt.Errorf("conf.d/%s: %w", n, err)
		}
		base = mergeMaps(base, extra)
	}
	return base, nil
}

// finalizeConfig applies env + --set overrides to the merged map, then
// decodes it into a validated Config.
func finalizeConfig(base map[string]any, sets []string) (*Config, error) {
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "TARPIT_") {
			continue
		}
		i := strings.IndexByte(env, '=')
		if i < 0 {
			continue
		}
		k, v := env[7:i], env[i+1:]
		applyDot(base, envKeyToPath(k), parseScalar(v))
	}
	for _, s := range sets {
		i := strings.IndexByte(s, '=')
		if i < 0 {
			return nil, fmt.Errorf("--set %q: expected key.path=value", s)
		}
		applyDot(base, strings.Split(s[:i], "."), parseScalar(s[i+1:]))
	}
	out, err := yaml.Marshal(base)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(out, &c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// readYAMLMap reads a YAML file into a generic map. Empty files / `{}` /
// pure-comment files all yield an empty map.
func readYAMLMap(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	out := map[string]any{}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return normalizeMap(out), nil
}

// normalizeMap converts yaml's map[interface{}]interface{} (legacy v2
// behavior) into map[string]any so our merge / dot-walk code can rely
// on string keys.
func normalizeMap(in map[string]any) map[string]any {
	for k, v := range in {
		in[k] = normalizeValue(v)
	}
	return in
}

func normalizeValue(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := map[string]any{}
		for k, val := range t {
			out[fmt.Sprintf("%v", k)] = normalizeValue(val)
		}
		return out
	case map[string]any:
		return normalizeMap(t)
	case []any:
		for i, x := range t {
			t[i] = normalizeValue(x)
		}
		return t
	}
	return v
}

// mergeMaps deep-merges b into a (b wins). Lists are replaced, not
// concatenated — operators can't append to e.g. listeners by accident
// from an include file. To extend a list, the include file would have
// to repeat the base entries.
func mergeMaps(a, b map[string]any) map[string]any {
	if a == nil {
		return b
	}
	for k, bv := range b {
		av, ok := a[k]
		if !ok {
			a[k] = bv
			continue
		}
		amap, aok := av.(map[string]any)
		bmap, bok := bv.(map[string]any)
		if aok && bok {
			a[k] = mergeMaps(amap, bmap)
			continue
		}
		a[k] = bv
	}
	return a
}

// combineMaps deep-merges b into a like mergeMaps, except that when both
// values are lists it APPENDS (a then b) instead of replacing. This is the
// "combine multiple -c files" semantics: every listener / honeynet / host
// across all files is kept, while scalar config (sensor.*, ui, ...) takes
// the later file's value.
func combineMaps(a, b map[string]any) map[string]any {
	if a == nil {
		return b
	}
	for k, bv := range b {
		av, ok := a[k]
		if !ok {
			a[k] = bv
			continue
		}
		if am, aok := av.(map[string]any); aok {
			if bm, bok := bv.(map[string]any); bok {
				a[k] = combineMaps(am, bm)
				continue
			}
		}
		if al, aok := av.([]any); aok {
			if bl, bok := bv.([]any); bok {
				a[k] = append(al, bl...)
				continue
			}
		}
		a[k] = bv
	}
	return a
}

// envKeyToPath converts TARPIT_SENSOR__NAME or TARPIT_SENSOR_NAME into
// ["sensor", "name"]. Double underscore is the "real underscore in key
// name" escape; single underscore is path separator. Lowercase output.
func envKeyToPath(s string) []string {
	parts := []string{}
	cur := []rune{}
	runes := []rune(strings.ToLower(s))
	for i := 0; i < len(runes); i++ {
		if runes[i] == '_' {
			if i+1 < len(runes) && runes[i+1] == '_' {
				cur = append(cur, '_')
				i++
				continue
			}
			parts = append(parts, string(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, runes[i])
	}
	if len(cur) > 0 {
		parts = append(parts, string(cur))
	}
	return parts
}

// applyDot drills into m by the path components and sets the final
// segment to v. Intermediate missing maps are created. If an
// intermediate path collides with a non-map scalar, the scalar is
// overwritten with a fresh map (the override always wins).
func applyDot(m map[string]any, path []string, v any) {
	if len(path) == 0 {
		return
	}
	for i := 0; i < len(path)-1; i++ {
		k := path[i]
		child, ok := m[k].(map[string]any)
		if !ok {
			child = map[string]any{}
			m[k] = child
		}
		m = child
	}
	m[path[len(path)-1]] = v
}

// parseScalar tries to coerce the string form of an override value into
// a sensible YAML scalar — bool/int/float/string. List / map syntax is
// not supported in --set or env overrides (use a conf.d fragment for
// that).
func parseScalar(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	case "null", "~":
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}
