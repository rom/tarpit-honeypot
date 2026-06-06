package handler

import (
	"slices"
	"strings"
	"testing"
)

// TestSSHNoAlgorithmAnachronisms guards the OpenSSH version -> algorithm-set
// timeline: an algorithm must never be advertised by a banner that predates
// the OpenSSH release which introduced it (Ed25519/Curve25519/chacha20 = 6.5;
// NIST ECC = 5.7). This is the "OpenSSH 5.3 offers ed25519" honeypot tell.
func TestSSHNoAlgorithmAnachronisms(t *testing.T) {
	has := func(set sshAlgoSet, name string) bool {
		return slices.Contains(set.hostKeys, name) || slices.Contains(set.kex, name) ||
			slices.Contains(set.ciphers, name)
	}
	cases := []struct {
		banner             string
		wantECC, want25519 bool
	}{
		{"SSH-2.0-OpenSSH_4.3", false, false}, // CentOS 5
		{"SSH-2.0-OpenSSH_5.3", false, false}, // CentOS 6
		{"SSH-2.0-OpenSSH_5.9", true, false},  // HPE OA: ECC yes, 25519 no
		{"SSH-2.0-OpenSSH_6.6.1", true, true}, // Ubuntu 14.04
		{"SSH-2.0-OpenSSH_9.6", true, true},   // modern
	}
	for _, c := range cases {
		set := sshAlgosForBanner(c.banner)
		gotECC := has(set, "ecdsa-sha2-nistp256")
		got25519 := has(set, "ssh-ed25519") || slices.ContainsFunc(set.kex, func(s string) bool {
			return strings.Contains(s, "curve25519")
		})
		if gotECC != c.wantECC {
			t.Errorf("%s: ECC=%v want %v", c.banner, gotECC, c.wantECC)
		}
		if got25519 != c.want25519 {
			t.Errorf("%s: 25519=%v want %v (anachronism!)", c.banner, got25519, c.want25519)
		}
		// chacha20 also first shipped in 6.5.
		gotChacha := slices.ContainsFunc(set.ciphers, func(s string) bool {
			return strings.Contains(s, "chacha20")
		})
		if gotChacha && !c.want25519 {
			t.Errorf("%s: offers chacha20 but predates OpenSSH 6.5", c.banner)
		}
	}
}

func TestOpenSSHVersionParse(t *testing.T) {
	cases := map[string][2]int{
		"ssh-2.0-openssh_5.3":   {5, 3},
		"ssh-2.0-openssh_9.6":   {9, 6},
		"ssh-2.0-openssh_8":     {8, 0},
		"ssh-2.0-openssh_6.6.1": {6, 6},
	}
	for b, want := range cases {
		maj, min, ok := openSSHVersion(b)
		if !ok || maj != want[0] || min != want[1] {
			t.Errorf("openSSHVersion(%q) = %d,%d,%v; want %d,%d", b, maj, min, ok, want[0], want[1])
		}
	}
	if _, _, ok := openSSHVersion("ssh-2.0-dropbear_2020.81"); ok {
		t.Error("dropbear banner should not parse as OpenSSH")
	}
}
