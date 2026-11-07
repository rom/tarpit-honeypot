package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdSchema emits a JSON Schema for the config file, derived by reflection over
// the config.Config type so it never drifts from the code. Point an editor's
// YAML language server at it (yaml.schemas) and the config gets structural
// validation + autocomplete — which turns authoring mistakes like the
// port-outside-bind / missing-id crash into red squiggles at edit time.
//
//	tarpit-honeypot schema > tarpit-honeypot.schema.json
func cmdSchema(args []string) error {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file instead of stdout")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	root := schemaFor(reflect.TypeOf(config.Config{}), map[reflect.Type]bool{})
	doc := map[string]any{
		"$schema":     "http://json-schema.org/draft-07/schema#",
		"title":       "tarpit-honeypot config",
		"description": "Structural schema for a tarpit-honeypot YAML config, generated from the Go config type. Durations are Go-style strings (e.g. \"5m\", \"30s\").",
	}
	for k, v := range root {
		doc[k] = v
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote JSON Schema to %s (%d properties at top level)\n", *out, len(root["properties"].(map[string]any)))
		return nil
	}
	_, err = os.Stdout.Write(b)
	return err
}

// schemaEnums pins the known closed vocabularies by yaml field name, so editors
// offer/validate the exact allowed values. Keyed by the leaf yaml key.
var schemaEnums = map[string][]string{
	"proto":    {"tcp", "udp"},
	"mode":     {"banner", "tarpit", "proxy", "script"},
	"severity": {"low", "medium", "high", "critical"},
	"format":   {"json", "cef", "leef", "ocsf"},
	"type":     {"stdout", "sqlite", "jsonlog", "syslog", "webhook", "discord", "mqtt", "snmptrap", "awssns", "smtp", "twilio"},
}

// schemaFor builds a JSON Schema fragment for a Go type. seen guards against
// recursive types (emits a bare object on a repeat).
func schemaFor(t reflect.Type, seen map[reflect.Type]bool) map[string]any {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// Go durations serialize as strings ("5m"); time.Time as an RFC3339 string.
	if t.PkgPath() == "time" && (t.Name() == "Duration" || t.Name() == "Time") {
		return map[string]any{"type": "string"}
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 { // []byte
			return map[string]any{"type": "string"}
		}
		return map[string]any{"type": "array", "items": schemaFor(t.Elem(), seen)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaFor(t.Elem(), seen)}
	case reflect.Interface:
		return map[string]any{} // any
	case reflect.Struct:
		if seen[t] {
			return map[string]any{"type": "object"}
		}
		seen[t] = true
		defer delete(seen, t)
		props := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // unexported
				continue
			}
			tag := f.Tag.Get("yaml")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" {
				continue
			}
			sub := schemaFor(f.Type, seen)
			if enum, ok := schemaEnums[name]; ok && sub["type"] == "string" {
				sub["enum"] = enum
			}
			props[name] = sub
		}
		return map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	}
	return map[string]any{}
}
