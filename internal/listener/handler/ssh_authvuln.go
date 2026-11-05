package handler

import "strings"

// SSH password-based auth-bypass / enumeration detection, shared by the
// interactive SSH handler. Everything here is detection + believable emulation;
// no credential ever grants real access (the post-login shell runs nothing).
//
// Signals, by captured password length L and target account:
//   - L > 256                → ssh-oversized-password (the ">256 byte password"
//     critical alarm) + the *sshole CVE hit (critical).
//   - 257 ≤ L ≤ 1024          → ssh-sshole-attempt: the exact musl locked-account
//     bypass window (musl crypt() returns "*" on failure == the locked marker).
//   - L ≥ ssholeEnumMinLen    → ssh-user-enum-timing + CVE-2016-6210: the giant
//     password forces the server down the slow hash path, the classic OpenSSH
//     <7.3 username-enumeration timing oracle.
//   - blank password to a privileged/locked account → ssh-alpine-blank-root +
//     CVE-2019-5021 (Alpine Docker images shipped root with a blank password).

const (
	// ssholeMinLen / ssholeMaxLen bound the *sshole musl password-bypass window
	// (OpenSSH on musl/Alpine without PAM accepts any 257–1024 byte password for
	// a '*'-locked account). musl caps crypt() input at 256 bytes and refuses
	// anything longer, so a password of 257..1024 is the on-wire signature.
	ssholeMinLen = 257
	ssholeMaxLen = 1024
	// oversizedPasswordLen is the ">256 byte password" critical-alarm threshold.
	oversizedPasswordLen = 256
	// ssholeEnumMinLen is the (very large) password length that marks a
	// CVE-2016-6210 user-enumeration timing probe rather than a plain bypass.
	ssholeEnumMinLen = 2048
)

// sshRootish reports whether a username is a privileged or commonly-locked
// system account — the targets of the Alpine blank-password and *sshole
// locked-account bypasses.
func sshRootish(user string) bool {
	switch strings.ToLower(strings.TrimSpace(user)) {
	case "root", "toor", "admin", "administrator", "sshd", "daemon", "operator", "sys", "bin":
		return true
	}
	return false
}

// sshBypassAccept reports whether an auth attempt matches an SSH bypass the
// honeypot emulates as "successful" when vuln emulation is on (so the attacker
// is trapped in the fake shell): the *sshole 257–1024 byte window, or a blank
// password to a privileged/locked account (CVE-2019-5021).
func sshBypassAccept(user string, passLen int) bool {
	if passLen >= ssholeMinLen && passLen <= ssholeMaxLen {
		return true
	}
	if passLen == 0 && sshRootish(user) {
		return true
	}
	return false
}

// scanSSHAuthThreats inspects captured password attempts and stamps the auth-
// bypass / enumeration anomalies + CVE hits onto res. Detection is independent
// of vuln emulation (which only controls whether the trap accepts the login).
func scanSSHAuthThreats(res *Result, attempts []map[string]any) {
	maxLen := -1
	for _, a := range attempts {
		if a["method"] != "password" {
			continue
		}
		n, _ := a["pass_len"].(int)
		if n > maxLen {
			maxLen = n
		}
		user, _ := a["user"].(string)

		if n == 0 && sshRootish(user) {
			flagAnomaly(res, "ssh-alpine-blank-root")
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2019-5021")
			setIfEmpty(res.Meta, "intent", "SSH blank-password login to a privileged account — Alpine CVE-2019-5021")
		}
		if n >= ssholeEnumMinLen {
			flagAnomaly(res, "ssh-user-enum-timing")
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2016-6210")
		}
	}

	if maxLen > oversizedPasswordLen {
		flagAnomaly(res, "ssh-oversized-password")
		res.Meta["max_password_len"] = maxLen
		// The *sshole technique is the >256-byte SSH password; attribute the
		// critical CVE hit to it across the whole oversized range.
		res.CVEHits = appendUnique(res.CVEHits, "SSHHOLE-2026")
		if maxLen <= ssholeMaxLen {
			flagAnomaly(res, "ssh-sshole-attempt")
			setIfEmpty(res.Meta, "intent", "SSH 257–1024 byte password to a locked account — *sshole musl bypass (sshhole.com)")
		} else {
			setIfEmpty(res.Meta, "intent", "SSH oversized (>256 byte) password — credential/auth-bypass attempt")
		}
	}
}
