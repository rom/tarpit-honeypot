package handler

import (
	"strings"
	"testing"
)

func TestPOP3PassOverflowFlagged(t *testing.T) {
	long := strings.Repeat("A", 600)
	res := runConn(t, &pop3{}, "USER admin\r\nPASS "+long+"\r\nQUIT\r\n")
	if !hasAnomaly(res, "pop3-pass-overflow") {
		t.Errorf("overlong PASS not flagged: %v", res.Meta["anomalies"])
	}
	if !containsStr(res.CVEHits, "CVE-2003-0264") {
		t.Errorf("PASS overflow should map to CVE-2003-0264; got %v", res.CVEHits)
	}
}

func TestPOP3STLSInjectionFlagged(t *testing.T) {
	// Plaintext command pipelined after STLS in one segment = injection probe.
	res := runConn(t, &pop3{}, "STLS\r\nUSER hacker\r\nPASS x\r\nQUIT\r\n")
	if !hasAnomaly(res, "starttls-command-injection") {
		t.Errorf("STLS injection not flagged: %v", res.Meta["anomalies"])
	}
	if !containsStr(res.CVEHits, "CVE-2011-1430") {
		t.Errorf("STLS injection should map to CVE-2011-1430; got %v", res.CVEHits)
	}
}

func TestPOP3VulnBanner(t *testing.T) {
	res := runConn(t, &pop3{vuln: true}, "CAPA\r\nQUIT\r\n")
	if res.Meta["emulated_software"] != "Dovecot "+vulnDovecotVersion {
		t.Errorf("vuln emulation not stamped: %v", res.Meta["emulated_software"])
	}
	cves, _ := res.Meta["emulated_vuln_cves"].([]string)
	if !containsStr(cves, "CVE-2003-0264") {
		t.Errorf("expected advertised pop3 CVEs; got %v", cves)
	}
	// A non-vuln server must not advertise a version or CVEs.
	clean := runConn(t, &pop3{}, "CAPA\r\nQUIT\r\n")
	if clean.Meta["emulated_software"] != nil {
		t.Errorf("non-vuln pop3 should not advertise software: %v", clean.Meta["emulated_software"])
	}
}

func TestIMAPLoginOverflowFlagged(t *testing.T) {
	long := strings.Repeat("B", 600)
	res := runConn(t, &imap{}, "a1 LOGIN admin "+long+"\r\na2 LOGOUT\r\n")
	if !hasAnomaly(res, "imap-login-overflow") {
		t.Errorf("overlong LOGIN not flagged: %v", res.Meta["anomalies"])
	}
	if !containsStr(res.CVEHits, "CVE-2019-11500") {
		t.Errorf("LOGIN overflow should map to CVE-2019-11500; got %v", res.CVEHits)
	}
}

func TestIMAPLiteralNULFlagged(t *testing.T) {
	// A NUL inside a pre-auth command is the CVE-2019-11500 trigger shape.
	res := runConn(t, &imap{}, "a1 LOGIN ad\x00min p\r\na2 LOGOUT\r\n")
	if !hasAnomaly(res, "imap-literal-nul") {
		t.Errorf("NUL byte not flagged: %v", res.Meta["anomalies"])
	}
	if !containsStr(res.CVEHits, "CVE-2019-11500") {
		t.Errorf("NUL literal should map to CVE-2019-11500; got %v", res.CVEHits)
	}
}

func TestIMAPOversizeLiteralFlagged(t *testing.T) {
	res := runConn(t, &imap{}, "a1 LOGIN {99999999}\r\na2 LOGOUT\r\n")
	if !hasAnomaly(res, "imap-literal-oversize") {
		t.Errorf("oversize literal not flagged: %v", res.Meta["anomalies"])
	}
}

func TestIMAPSTARTTLSInjectionFlagged(t *testing.T) {
	res := runConn(t, &imap{}, "a1 STARTTLS\r\na2 LOGIN evil pass\r\na3 LOGOUT\r\n")
	if !hasAnomaly(res, "starttls-command-injection") {
		t.Errorf("STARTTLS injection not flagged: %v", res.Meta["anomalies"])
	}
	if !containsStr(res.CVEHits, "CVE-2011-1430") {
		t.Errorf("STARTTLS injection should map to CVE-2011-1430; got %v", res.CVEHits)
	}
}

func TestIMAPVulnBanner(t *testing.T) {
	res := runConn(t, &imap{vuln: true}, "a1 CAPABILITY\r\na2 LOGOUT\r\n")
	if res.Meta["emulated_software"] != "Dovecot "+vulnDovecotVersion {
		t.Errorf("vuln emulation not stamped: %v", res.Meta["emulated_software"])
	}
}

func TestMailNormalLoginNotFlaggedAsOverflow(t *testing.T) {
	// A realistic login must NOT trip the overflow/injection detectors.
	res := runConn(t, &pop3{}, "USER alice\r\nPASS hunter2\r\nQUIT\r\n")
	if hasAnomaly(res, "pop3-pass-overflow") || len(res.CVEHits) != 0 {
		t.Errorf("benign login misflagged: anomalies=%v cves=%v", res.Meta["anomalies"], res.CVEHits)
	}
}

func TestIMAPLiteralLenParse(t *testing.T) {
	cases := map[string]int{
		"a LOGIN {12}":     12,
		"a LOGIN {4096+}":  4096,
		"a LOGIN user":     -1,
		"a LOGIN {x}":      -1,
		"a LOGIN {12} foo": -1, // literal must be at end of line
	}
	for in, want := range cases {
		n, ok := imapLiteralLen(in)
		if want < 0 {
			if ok {
				t.Errorf("imapLiteralLen(%q) = %d, want no match", in, n)
			}
			continue
		}
		if !ok || n != want {
			t.Errorf("imapLiteralLen(%q) = %d,%v; want %d", in, n, ok, want)
		}
	}
}
