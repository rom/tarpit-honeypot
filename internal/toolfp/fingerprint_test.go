package toolfp

import "testing"

func TestJA4Automation(t *testing.T) {
	cases := []struct {
		name string
		ja4  string
		auto bool
	}{
		// Browser-shaped: ALPN h2, SNI domain, full suite → not automation.
		{"chrome-like", "t13d1516h2_8daaf6152771_02713d6af862", false},
		{"firefox-like h1", "t13d1715h1_5b57614c22b0_7121afd63a22", false},
		// No ALPN (00) → non-browser TLS.
		{"no-alpn", "t13d150600_abcdef012345_012345abcdef", true},
		// No ALPN + no SNI (i) → non-browser, with no-SNI in the reason.
		{"no-alpn-no-sni", "t13i020400_aaaaaaaaaaaa_bbbbbbbbbbbb", true},
		// QUIC with no ALPN still parses.
		{"quic-no-alpn", "q13d010100_aaaaaaaaaaaa_bbbbbbbbbbbb", true},
		// Unparseable / too short → never automation.
		{"short", "t13d", false},
		{"empty", "", false},
		{"bad-proto", "x13d150600_x_y", false},
	}
	for _, c := range cases {
		reason, auto := JA4Automation(c.ja4)
		if auto != c.auto {
			t.Errorf("%s: JA4Automation(%q) auto=%v want %v (reason %q)", c.name, c.ja4, auto, c.auto, reason)
		}
		if auto && reason == "" {
			t.Errorf("%s: automation true but empty reason", c.name)
		}
	}
	// The no-SNI case should name it in the reason.
	if r, _ := JA4Automation("t13i020400_a_b"); r == "" {
		t.Error("no-SNI no-ALPN should report a reason")
	}
}

func TestIdentifyJA4AndHASSHExtensible(t *testing.T) {
	// Empty by default (operator/corpus-extensible) — must not panic or match.
	if IdentifyJA4("whatever") != "" {
		t.Error("unseeded JA4 should not match")
	}
	if IdentifyHASSH("deadbeef") != "" {
		t.Error("unseeded HASSH should not match")
	}
	// A seeded entry resolves (prove the lookup path works).
	ja4Signatures["t13d000000_x_y"] = "unit-test-tool"
	defer delete(ja4Signatures, "t13d000000_x_y")
	if IdentifyJA4("  t13d000000_x_y  ") != "unit-test-tool" {
		t.Error("seeded JA4 (trimmed) should resolve")
	}
}

func TestLooksLikeBrowserUA(t *testing.T) {
	if !LooksLikeBrowserUA("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0") {
		t.Error("a Chrome UA should look like a browser")
	}
	if LooksLikeBrowserUA("python-requests/2.31") {
		t.Error("python-requests must not look like a browser")
	}
}
