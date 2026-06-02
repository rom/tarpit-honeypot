package handler

import (
	"bufio"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Mail (POP3/IMAP) vulnerability-emulation + protocol-misimplementation
// detection, shared by the plaintext handlers and — because the implicit-TLS
// variants (pop3s/imaps) wrap the same handler after the TLS handshake — by the
// encrypted variants too. Three things live here:
//
//   1. Vuln-banner emulation: when sensor.vuln_emulation is on, the handlers
//      advertise a specific known-vulnerable Dovecot version so a scanner
//      fingerprints the box as exploitable, and surface the advertised CVEs in
//      meta.emulated_vuln_cves.
//   2. Detectors for the two classic mail protocol-misimplementation attacks:
//      the STARTTLS/STLS plaintext command-injection probe (CVE-2011-1430
//      class) and pre-auth credential/literal buffer-overflow probes
//      (CVE-2003-0264 POP3 PASS, CVE-2019-11500 IMAP literal). They flag an
//      anomaly and record the matched CVE — detection only; we never execute
//      the injected bytes or actually overflow.
//   3. cveScanMail runs the generic signature catalog over the captured bytes.

// vulnDovecotVersion is the version advertised under vuln emulation. 2.3.7.1
// predates the CVE-2019-11500 fix (2.3.7.2 / 2.2.36.4) and sits in the lineage
// affected by the STARTTLS plaintext-injection class.
const vulnDovecotVersion = "2.3.7.1"

// mailCredOverflowLen is the pre-auth credential/argument length past which we
// treat a login attempt as a buffer-overflow probe rather than a real login.
// RFC mailboxes/passwords are far shorter; classic overflow PoCs send hundreds
// to thousands of bytes.
const mailCredOverflowLen = 256

// mailVulnCVEs lists the CVEs the vulnerable emulation advertises for a service
// ("pop3" / "imap"), surfaced in meta.emulated_vuln_cves when vuln is on.
func mailVulnCVEs(service string) []string {
	switch service {
	case "pop3":
		return []string{"CVE-2011-1430", "CVE-2003-0264"}
	case "imap":
		return []string{"CVE-2019-11500", "CVE-2011-1430"}
	}
	return nil
}

// markMailVuln stamps the advertised vulnerable version + CVEs into meta. Call
// once when the banner is sent under vuln emulation.
func markMailVuln(res *Result, service string) {
	res.Meta["emulated_software"] = "Dovecot " + vulnDovecotVersion
	if cves := mailVulnCVEs(service); len(cves) > 0 {
		res.Meta["emulated_vuln_cves"] = cves
	}
}

// detectSTARTTLSInjection reports whether the client pipelined plaintext after
// the STARTTLS/STLS command but before the TLS handshake — the STARTTLS
// command-injection probe (CVE-2011-1430 class). br holds any read-ahead bytes
// bufio already pulled off the socket. The caller rebuilds its reader over the
// TLS conn afterwards, so the buffered plaintext is dropped, never executed; we
// only record the attempt.
func detectSTARTTLSInjection(br *bufio.Reader, res *Result, cveID string) {
	n := br.Buffered()
	if n <= 0 {
		return
	}
	peek, _ := br.Peek(n)
	flagAnomaly(res, "starttls-command-injection")
	res.Meta["starttls_injected"] = safe.SanitizeForLog(string(peek))
	res.CVEHits = appendUnique(res.CVEHits, cveID)
}

// detectCredOverflow flags a pre-auth credential/argument longer than
// mailCredOverflowLen as a buffer-overflow probe and records the mapped CVE.
// field is e.g. "pass" / "user" / "login"; service is "pop3" / "imap".
func detectCredOverflow(res *Result, service, field, value, cveID string) bool {
	if len(value) <= mailCredOverflowLen {
		return false
	}
	flagAnomaly(res, service+"-"+field+"-overflow")
	res.Meta["overflow_field"] = field
	res.Meta["overflow_len"] = len(value)
	res.CVEHits = appendUnique(res.CVEHits, cveID)
	return true
}

// detectIMAPLiteralOOB flags the CVE-2019-11500 trigger shape: a pre-auth
// command carrying a NUL byte, or an IMAP literal "{N}" / "{N+}" announcing an
// absurd length. Dovecot < 2.3.7.2 mishandled these into an out-of-bounds write.
func detectIMAPLiteralOOB(line string, res *Result) bool {
	if strings.IndexByte(line, 0) >= 0 {
		flagAnomaly(res, "imap-literal-nul")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2019-11500")
		return true
	}
	if n, ok := imapLiteralLen(line); ok && n > 1<<20 { // > 1 MiB announced pre-auth
		flagAnomaly(res, "imap-literal-oversize")
		res.Meta["literal_len"] = n
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2019-11500")
		return true
	}
	return false
}

// imapLiteralLen parses a trailing IMAP literal "{N}" or non-synchronizing
// "{N+}" off the end of a command line, returning the announced octet count.
func imapLiteralLen(line string) (int, bool) {
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasSuffix(line, "}") {
		return 0, false
	}
	open := strings.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false
	}
	inner := strings.TrimSuffix(line[open+1:], "}")
	inner = strings.TrimSuffix(inner, "+") // non-synchronizing literal
	n, err := strconv.Atoi(inner)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// cveScanMail runs the generic signature catalog over the captured bytes for a
// mail service and merges any hits (keeps parity with the http/smb handlers and
// picks up future catalogued pop3/imap signatures).
func cveScanMail(res *Result, service string) {
	for _, rec := range cve.MatchPayload(service, string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
	}
}
