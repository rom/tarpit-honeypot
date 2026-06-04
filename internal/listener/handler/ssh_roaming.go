package handler

import (
	"regexp"
	"strconv"
	"strings"
)

// openSSHVerRe pulls the major.minor out of an OpenSSH client identification
// string ("SSH-2.0-OpenSSH_7.1p2 Debian-…" -> "7","1").
var openSSHVerRe = regexp.MustCompile(`openssh[_-]([0-9]+)\.([0-9]+)`)

// openSSHRoamingVulnerable reports whether an SSH client identification banner
// belongs to an OpenSSH version in the CVE-2016-0777 / CVE-2016-0778 "roaming"
// window. OpenSSH 5.4 through 7.1 shipped the undocumented client roaming
// feature *enabled by default*; a malicious server can abuse it to read the
// client process's heap and disclose the user's private key (0777), or to
// overflow a client buffer (0778). The honeypot is the server, so it sees the
// client version in clear text before key exchange — a vulnerable client is
// exactly the precondition the attack needs.
func openSSHRoamingVulnerable(clientID string) (version string, vulnerable bool) {
	m := openSSHVerRe.FindStringSubmatch(strings.ToLower(clientID))
	if m == nil {
		return "", false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	version = m[1] + "." + m[2]
	switch {
	case major == 5 && minor >= 4:
		return version, true
	case major == 6:
		return version, true
	case major == 7 && minor <= 1:
		return version, true
	}
	return version, false
}

// flagSSHRoaming stamps the CVE-2016-0777 / CVE-2016-0778 roaming key-leak
// detection on res when the client banner is a vulnerable OpenSSH version.
//
// On "getting the client keys": full private-key extraction requires driving
// the OpenSSH roaming *resume* exchange (the client re-sends buffered session
// state, including over-read heap memory, on reconnect). That wire protocol is
// not expressible through golang.org/x/crypto/ssh, so the honeypot cannot
// complete the disclosure. What it does capture is (a) the vulnerable-client
// signal recorded here, and (b) every public key the client offers during
// authentication (see ssh_interactive's PublicKeyCallback, surfaced as
// ssh_pubkey_fps) — a strong reuse/attribution indicator.
func flagSSHRoaming(res *Result, clientID string) {
	ver, ok := openSSHRoamingVulnerable(clientID)
	if !ok {
		return
	}
	res.CVEHits = appendUnique(res.CVEHits, "CVE-2016-0777")
	res.CVEHits = appendUnique(res.CVEHits, "CVE-2016-0778")
	flagAnomaly(res, "ssh-roaming-vulnerable-client")
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["ssh_client_openssh_version"] = ver
}
