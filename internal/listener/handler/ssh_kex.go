package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// sshAlgoSet is the algorithm name-lists an SSH server advertises in its
// KEXINIT (RFC 4253 §7.1). It drives the server's HASSH fingerprint, so a
// modern OpenSSH, a legacy OpenSSH/Cisco, and a Dropbear box present
// distinct sets — and, crucially, a set that is *consistent with the
// version banner we already sent* (a "banner says OpenSSH 9.2 but the
// KEXINIT looks like 7.4" mismatch is a honeypot tell). c2s and s2c lists
// are identical, exactly as real OpenSSH emits them.
type sshAlgoSet struct {
	kex      []string
	hostKeys []string
	ciphers  []string
	macs     []string
	comp     []string
}

// sshModern is a current OpenSSH (9.x) algorithm set.
var sshModern = sshAlgoSet{
	kex: []string{
		"sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
		"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
		"ext-info-s", "kex-strict-s-v00@openssh.com",
	},
	hostKeys: []string{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"},
	ciphers: []string{
		"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	},
	macs: []string{
		"umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
	},
	comp: []string{"none", "zlib@openssh.com"},
}

// sshLegacy is an older OpenSSH / network-OS set (pre-8.0 era): ssh-rsa
// host key, CBC + 3des ciphers, group1/14-sha1 KEX.
var sshLegacy = sshAlgoSet{
	kex: []string{
		"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
	},
	hostKeys: []string{"ssh-rsa", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"},
	ciphers: []string{
		"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
	},
	macs: []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
	},
	comp: []string{"none", "zlib@openssh.com"},
}

// sshDropbear is the smaller set Dropbear (embedded routers / cameras /
// Teltonika) advertises.
var sshDropbear = sshAlgoSet{
	kex: []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp521",
		"ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1",
	},
	hostKeys: []string{"ssh-rsa", "ssh-ed25519"},
	ciphers:  []string{"aes128-ctr", "aes256-ctr"},
	macs:     []string{"hmac-sha2-256", "hmac-sha1"},
	comp:     []string{"none", "zlib@openssh.com"},
}

// sshAlgosForBanner picks the algorithm set consistent with the SSH version
// banner, so the server KEXINIT (and its HASSH) matches what a real install
// of that software would emit.
func sshAlgosForBanner(banner string) sshAlgoSet {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "dropbear"):
		return sshDropbear
	case strings.Contains(b, "rosssh"), strings.Contains(b, "cisco"):
		return sshLegacy
	case oldOpenSSHMajor(b):
		return sshLegacy
	default:
		return sshModern
	}
}

// oldOpenSSHMajor reports whether the (lowercased) banner names an OpenSSH
// release older than 8.0.
func oldOpenSSHMajor(b string) bool {
	i := strings.Index(b, "openssh_")
	if i < 0 {
		return false
	}
	rest := b[i+len("openssh_"):]
	n, got := 0, false
	for j := 0; j < len(rest) && rest[j] >= '0' && rest[j] <= '9'; j++ {
		n = n*10 + int(rest[j]-'0')
		got = true
	}
	return got && n < 8
}

// buildKEXINITPayload renders an SSH_MSG_KEXINIT payload (starting at the
// 0x14 type byte) for the given algorithm set, with a random cookie. This
// is both sent on the wire (after framing) and fed to fingerprint.HASSH.
func buildKEXINITPayload(set sshAlgoSet) []byte {
	var b bytes.Buffer
	b.WriteByte(0x14) // SSH_MSG_KEXINIT
	var cookie [16]byte
	_, _ = rand.Read(cookie[:])
	b.Write(cookie[:])
	putNameList(&b, set.kex)
	putNameList(&b, set.hostKeys)
	putNameList(&b, set.ciphers) // encryption c2s
	putNameList(&b, set.ciphers) // encryption s2c
	putNameList(&b, set.macs)    // mac c2s
	putNameList(&b, set.macs)    // mac s2c
	putNameList(&b, set.comp)    // compression c2s
	putNameList(&b, set.comp)    // compression s2c
	putNameList(&b, nil)         // languages c2s
	putNameList(&b, nil)         // languages s2c
	b.WriteByte(0)               // first_kex_packet_follows = false
	b.Write([]byte{0, 0, 0, 0})  // reserved
	return b.Bytes()
}

// putNameList writes an SSH name-list (uint32 length + comma-joined string).
func putNameList(b *bytes.Buffer, items []string) {
	s := strings.Join(items, ",")
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	b.Write(l[:])
	b.WriteString(s)
}

// frameSSHPacket wraps a payload in the SSH binary packet framing (RFC 4253
// §6) for the "none" cipher: a 4-byte packet length, 1-byte padding length,
// the payload, then >=4 bytes of random padding so the total is a multiple
// of 8.
func frameSSHPacket(payload []byte) []byte {
	base := 4 + 1 + len(payload)
	pad := 8 - (base % 8)
	if pad < 4 {
		pad += 8
	}
	packetLen := 1 + len(payload) + pad
	out := make([]byte, 0, 4+packetLen)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(packetLen))
	out = append(out, lb[:]...)
	out = append(out, byte(pad))
	out = append(out, payload...)
	padding := make([]byte, pad)
	_, _ = rand.Read(padding)
	out = append(out, padding...)
	return out
}
