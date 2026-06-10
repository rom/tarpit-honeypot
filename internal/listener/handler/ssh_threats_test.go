package handler

import (
	"encoding/binary"
	"testing"
)

func TestSSHTerrapinAndNone(t *testing.T) {
	// Vulnerable: no kex-strict, chacha20 offered.
	vuln := &sshKexInit{
		kex:    []string{"curve25519-sha256", "ext-info-c"},
		encC2S: []string{"chacha20-poly1305@openssh.com"},
		encS2C: []string{"chacha20-poly1305@openssh.com"},
	}
	if !sshTerrapinVulnerable(vuln) {
		t.Error("chacha20 without kex-strict should be Terrapin-vulnerable")
	}
	// Protected: advertises kex-strict.
	safe := &sshKexInit{
		kex:    []string{"curve25519-sha256", "kex-strict-c-v00@openssh.com"},
		encC2S: []string{"chacha20-poly1305@openssh.com"},
	}
	if sshTerrapinVulnerable(safe) {
		t.Error("kex-strict client must not be flagged Terrapin-vulnerable")
	}
	// CBC without EtM MAC is not (by itself) the affected combo.
	cbcOnly := &sshKexInit{kex: []string{"x"}, encC2S: []string{"aes128-cbc"}, macC2S: []string{"hmac-sha2-256"}}
	if sshTerrapinVulnerable(cbcOnly) {
		t.Error("CBC without EtM MAC should not be flagged")
	}
	if !sshOffersNone(&sshKexInit{encC2S: []string{"none"}}) {
		t.Error("none cipher not detected")
	}
}

func TestSSHEnvPairShellshock(t *testing.T) {
	mk := func(name, val string) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(len(name)))
		b = append(b, name...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(val)))
		return append(b, val...)
	}
	n, v, ok := sshEnvPair(mk("X", "() { :;}; /bin/sh"))
	if !ok || n != "X" || v[:4] != "() {" {
		t.Fatalf("env pair parse failed: %q=%q ok=%v", n, v, ok)
	}
}
