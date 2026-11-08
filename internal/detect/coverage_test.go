package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestResolveFieldAll exercises every resolveField branch, the meta.* path, and
// the unknown-field fallthrough.
func TestResolveFieldAll(t *testing.T) {
	ev := &event.Event{
		Handler: "http", RuleID: "r1", Proto: "tcp", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "1.2.3.4"}, Dest: event.Endpoint{IP: "5.6.7.8", Port: 443},
		BannerSent: "banner", Sensor: "s1",
		Anomalies: []string{"a1", "a2"}, MitreTechniques: []string{"T1190"}, MitreTactics: []string{"initial-access"},
		Meta: map[string]any{"foo": map[string]any{"bar": "baz"}, "n": 7, "list": []any{"x", 2}},
	}
	checks := map[string]string{
		"handler": "http", "rule_id": "r1", "rule": "r1", "proto": "tcp", "severity": "high",
		"source_ip": "1.2.3.4", "src_ip": "1.2.3.4", "source": "1.2.3.4",
		"dest_ip": "5.6.7.8", "dst_ip": "5.6.7.8", "dest": "5.6.7.8",
		"dest_port": "443", "dst_port": "443", "port": "443",
		"banner": "banner", "sensor": "s1",
		"meta.foo.bar": "baz", "meta.n": "7",
	}
	for field, want := range checks {
		got := resolveField(ev, field)
		if len(got) == 0 || got[0] != want {
			t.Errorf("resolveField(%q) = %v, want [%q]", field, got, want)
		}
	}
	// slice-valued fields
	if got := resolveField(ev, "anomalies"); len(got) != 2 {
		t.Errorf("anomalies = %v", got)
	}
	if got := resolveField(ev, "techniques"); len(got) != 1 || got[0] != "T1190" {
		t.Errorf("techniques = %v", got)
	}
	if got := resolveField(ev, "tactics"); len(got) != 1 {
		t.Errorf("tactics = %v", got)
	}
	// meta list leaf flattens
	if got := resolveField(ev, "meta.list"); len(got) != 2 || got[0] != "x" || got[1] != "2" {
		t.Errorf("meta.list = %v", got)
	}
	// unknown field and missing meta path
	if got := resolveField(ev, "nope"); got != nil {
		t.Errorf("unknown field = %v, want nil", got)
	}
	if got := resolveField(ev, "meta.absent.x"); got != nil {
		t.Errorf("absent meta = %v, want nil", got)
	}
}

// TestToStringsTypes covers every toStrings type branch.
func TestToStringsTypes(t *testing.T) {
	cases := []struct {
		in   any
		want []string
	}{
		{nil, nil},
		{"s", []string{"s"}},
		{[]string{"a", "b"}, []string{"a", "b"}},
		{[]any{"a", 2, true}, []string{"a", "2", "true"}},
		{true, []string{"true"}},
		{7, []string{"7"}},
		{int64(9), []string{"9"}},
		{3.5, []string{"3.5"}},
		{struct{ X int }{1}, []string{"{1}"}}, // default %v
	}
	for _, c := range cases {
		got := toStrings(c.in)
		if len(got) != len(c.want) {
			t.Errorf("toStrings(%#v) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("toStrings(%#v)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestLoadApplyRoundTrip covers Load -> parseFile -> compile -> Count -> Apply
// -> matches -> eval with a real rule file.
func TestLoadApplyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rule := "- id: test-admin\n" +
		"  title: Admin banner\n" +
		"  severity: high\n" +
		"  tags: [test-admin-seen]\n" +
		"  match:\n" +
		"    handler: http\n" +
		"    meta.foo: bar\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, errs := Load(dir)
	if len(errs) != 0 {
		t.Fatalf("Load errors: %v", errs)
	}
	if eng.Count() != 1 {
		t.Fatalf("Count = %d, want 1", eng.Count())
	}
	// matching event: Apply returns the matched rule IDs and adds the rule's
	// tags (and detect:<id>) to the event's anomalies.
	ev := &event.Event{Handler: "http", Meta: map[string]any{"foo": "bar"}}
	matched := eng.Apply(ev)
	if len(matched) != 1 || matched[0] != "test-admin" {
		t.Errorf("Apply(match) = %v, want [test-admin]", matched)
	}
	var hasTag bool
	for _, a := range ev.Anomalies {
		if a == "test-admin-seen" {
			hasTag = true
		}
	}
	if !hasTag {
		t.Errorf("event anomalies %v missing rule tag test-admin-seen", ev.Anomalies)
	}
	// non-matching event (wrong handler)
	ev2 := &event.Event{Handler: "ftp", Meta: map[string]any{"foo": "bar"}}
	if tags := eng.Apply(ev2); len(tags) != 0 {
		t.Errorf("Apply(no match) tags = %v, want none", tags)
	}
	// nil engine is a no-op
	var nilEng *Engine
	if got := nilEng.Apply(ev); got != nil {
		t.Errorf("nil engine Apply = %v, want nil", got)
	}
}
