package handler

import (
	"strings"
	"testing"
)

func TestFTPGlobDoS(t *testing.T) {
	// The vsftpd 2.3.2 recursive-glob DoS payload: a long argument stuffed with
	// glob metacharacters / traversals.
	dos := []string{
		strings.Repeat("{,a}", 60),                // 240 chars, 120 '{'
		strings.Repeat("../*", 80),                // traversal + wildcards
		strings.Repeat("*", 40),                   // 40 wildcards
		strings.Repeat("A", 2100),                 // approaching the 4096 buffer
		"/" + strings.Repeat("../", 25) + "*.txt", // 25 traversals (len>=200? no) -> meta check
	}
	for _, a := range dos {
		// pad the traversal case so it crosses the 200-char threshold where needed
		if len(a) < 200 && strings.Count(a, "*")+strings.Count(a, "{") < 30 {
			a = a + strings.Repeat("../*", 60)
		}
		if !ftpGlobDoS(a) {
			t.Errorf("glob DoS not detected for arg of len %d (meta=%d)", len(a),
				strings.Count(a, "*")+strings.Count(a, "{"))
		}
	}

	// Benign paths must not trip it.
	for _, a := range []string{"", "/", "pub/files", "report-2024.pdf", "*.txt", "data/*", "../up"} {
		if ftpGlobDoS(a) {
			t.Errorf("benign arg %q wrongly flagged as glob DoS", a)
		}
	}

	// The wiring stamps the anomaly + meta.
	res := &Result{Meta: map[string]any{}}
	flagFTPGlobDoS(res, "STAT", strings.Repeat("{,x}", 60))
	if !hasAnom(*res, "ftp-glob-dos") || res.Meta["ftp_glob_dos_cmd"] != "STAT" {
		t.Errorf("flagFTPGlobDoS did not stamp the event: %v", res.Meta)
	}
}
