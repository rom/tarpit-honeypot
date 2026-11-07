package cli

import (
	"reflect"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestCollectListenerPorts(t *testing.T) {
	cfg := &config.Config{
		Listeners: []config.Listener{
			{ID: "modbus", Proto: "tcp", Bind: "0.0.0.0:502", Handler: "modbus"},
			{ID: "modbus-udp", Proto: "udp", Bind: "0.0.0.0:502", Handler: "modbus_udp"},
			{ID: "dup", Proto: "tcp", Bind: "0.0.0.0:502", Handler: "modbus"}, // dup tcp/502
			{ID: "v6", Proto: "tcp", Bind: "[::]:443", Handler: "https"},
			{ID: "bad", Proto: "tcp", Bind: "not-a-bind", Handler: "x"}, // skipped
		},
		Honeynets: []config.Honeynet{
			{ID: "sub", Hosts: []config.HoneynetHost{
				{Hostname: "plc", Services: []config.HoneynetService{{Port: 102, Handler: "s7"}}},
			}},
		},
	}
	got := collectListenerPorts(cfg)
	// Expect: tcp/102, tcp/443, tcp/502, udp/502 — dedup + bad skipped.
	want := map[string]bool{"tcp/102": true, "tcp/443": true, "tcp/502": true, "udp/502": true}
	if len(got) != len(want) {
		t.Fatalf("got %d ports, want %d: %+v", len(got), len(want), got)
	}
	for _, p := range got {
		k := p.proto + "/" + itoaPort(p.port)
		if !want[k] {
			t.Errorf("unexpected port %s", k)
		}
	}
	// Sorted: tcp before udp, ascending port.
	if got[0].proto != "tcp" || got[0].port != 102 {
		t.Errorf("not sorted; first = %+v", got[0])
	}
	if got[len(got)-1].proto != "udp" {
		t.Errorf("udp should sort last; last = %+v", got[len(got)-1])
	}
}

func itoaPort(p int) string {
	// tiny local helper to avoid importing strconv just for the test key
	return map[int]string{102: "102", 443: "443", 502: "502"}[p]
}

func TestSchemaForTypesAndEnums(t *testing.T) {
	type inner struct {
		Proto    string `yaml:"proto"`
		Severity string `yaml:"severity"`
		Name     string `yaml:"name"`
		Count    int    `yaml:"count"`
		On       bool   `yaml:"enabled"`
		Tags     []string
		hidden   string // unexported, no tag → skipped
	}
	s := schemaFor(reflect.TypeOf(inner{}), map[reflect.Type]bool{})
	props, _ := s["properties"].(map[string]any)
	if props == nil {
		t.Fatal("no properties")
	}
	// proto/severity carry closed enums.
	if proto, _ := props["proto"].(map[string]any); proto["enum"] == nil {
		t.Errorf("proto should have an enum: %v", props["proto"])
	}
	if sev, _ := props["severity"].(map[string]any); sev["type"] != "string" || sev["enum"] == nil {
		t.Errorf("severity should be a string with an enum: %v", props["severity"])
	}
	if c, _ := props["count"].(map[string]any); c["type"] != "integer" {
		t.Errorf("count should be integer: %v", props["count"])
	}
	if e, _ := props["enabled"].(map[string]any); e["type"] != "boolean" {
		t.Errorf("enabled should be boolean: %v", props["enabled"])
	}
	if _, ok := props["hidden"]; ok {
		t.Error("unexported/untagged field must be skipped")
	}
	if s["additionalProperties"] != false {
		t.Error("objects should disallow additionalProperties")
	}
}

func TestSchemaForFullConfigNoPanic(t *testing.T) {
	// The real driver: reflecting the whole Config must not panic or recurse
	// forever, and must yield a non-empty top-level property set.
	s := schemaFor(reflect.TypeOf(config.Config{}), map[reflect.Type]bool{})
	props, _ := s["properties"].(map[string]any)
	if len(props) == 0 {
		t.Fatal("config schema has no top-level properties")
	}
	for _, key := range []string{"sensor", "listeners", "channels", "taxii"} {
		if _, ok := props[key]; !ok {
			t.Errorf("expected top-level config key %q in schema", key)
		}
	}
}
