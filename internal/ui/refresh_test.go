package ui

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// headWithRefresh renders the shared head with a given refresh interval.
func headWithRefresh(t *testing.T, secs int) string {
	t.Helper()
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return secs }, "nvd", "")).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "head", nil); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestHeadAutoRefresh(t *testing.T) {
	on := headWithRefresh(t, 7)
	if !strings.Contains(on, `http-equiv="refresh" content="7"`) {
		t.Errorf("expected auto-refresh meta with content=7; got: %q", on)
	}
	off := headWithRefresh(t, 0)
	if strings.Contains(off, "http-equiv=\"refresh\"") {
		t.Errorf("refresh disabled (0) must not emit a refresh meta; got: %q", off)
	}
}
