package ui

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/correlate"
)

func TestPlaybooksPageRenders(t *testing.T) {
	s := &Server{tmpl: uiTmpl(t)}
	w := httptest.NewRecorder()
	s.handlePlaybooks(w, httptest.NewRequest("GET", "/playbooks?name=ot-kill-chain", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"attack playbooks", `id="ot-kill-chain"`, "ICS/OT kill chain",
		"operator next steps", "← selected", // the ?name= focus highlight
		`href="#credential-harvest"`, // the jump-to index
	} {
		if !strings.Contains(body, want) {
			t.Errorf("playbooks page missing %q", want)
		}
	}
	// Every registered playbook must render its own anchor section.
	for _, p := range correlate.AllPlaybooks() {
		if !strings.Contains(body, `id="`+p.Name+`"`) {
			t.Errorf("playbooks page missing section for %q", p.Name)
		}
	}
}
