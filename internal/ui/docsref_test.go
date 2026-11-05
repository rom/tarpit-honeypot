package ui

import (
	"strings"
	"testing"
)

func TestDocsReferenceCatalogs(t *testing.T) {
	if len(jaCatalog()) < 5 {
		t.Error("ja catalog too small")
	}
	h := handlerDocs()
	if len(h) < 50 {
		t.Errorf("handler docs too small: %d", len(h))
	}
	// pop3/imap must be documented with their real descriptions.
	var sawPop3 bool
	for _, d := range h {
		if d.Name == "pop3" {
			sawPop3 = true
			if !strings.Contains(d.Desc, "POP3") {
				t.Errorf("pop3 desc = %q", d.Desc)
			}
		}
	}
	if !sawPop3 {
		t.Error("pop3 handler not documented")
	}
	if len(techniqueDocs()) < 20 {
		t.Error("technique docs too small")
	}
	cves := cveDocs()
	if len(cves) < 20 {
		t.Errorf("cve docs too small: %d", len(cves))
	}
	// Every documented catalog entry carries a canonical (uppercase) id: a CVE,
	// or — for a disclosed vuln with no assigned CVE — an advisory id such as
	// "SSHHOLE-2026".
	for _, c := range cves {
		if c.ID == "" || c.ID != strings.ToUpper(c.ID) {
			t.Errorf("bad catalog id %q", c.ID)
		}
		if !strings.HasPrefix(c.ID, "CVE-") && !strings.ContainsAny(c.ID, "0123456789") {
			t.Errorf("non-CVE catalog id %q should still carry a year/number", c.ID)
		}
	}
}
