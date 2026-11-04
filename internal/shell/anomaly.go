package shell

import "strings"

// ScanAnomalies returns ATT&CK-relevant markers for a single command
// line. Exported so SSH-interactive's non-interactive "exec" path can
// classify the one-shot command attempted by the attacker. See
// scanAnomalies for the marker -> ATT&CK technique mapping.
func ScanAnomalies(line string) []string {
	return scanAnomalies(line)
}

// scanAnomalies returns ATT&CK-relevant markers for a single command
// line. The matchers are intentionally over-broad — false positives
// in a honeypot context only mean "interesting attacker behavior",
// not "broken response". Each marker maps to an ATT&CK technique:
//
//	shell-reverse-shell        T1059 / T1071  (execution + C2)
//	shell-download-tool        T1105          (ingress tool transfer)
//	shell-persistence-ssh-key  T1098.004      (account manipulation)
//	shell-persistence-cron     T1053.003      (cron job)
//	shell-shadow-read          T1003.008      (credential access from /etc/shadow)
//	shell-passwd-read          T1003          (OS credential dumping)
//	shell-priv-esc-suid        T1548.001      (setuid abuse)
//	shell-priv-esc-sudo        T1548.003      (sudo abuse)
//	shell-defense-evade-history T1070.003     (clear command history)
//	shell-defense-evade-logclean T1070.002    (clear logs)
//	shell-living-off-the-land  T1059.004      (lol-bin abuse)
//	shell-coin-miner           T1496          (resource hijacking)
//	shell-network-recon        T1018          (remote system discovery)
//	shell-disable-fw           T1562.004      (disable firewall)
//	shell-encoded-payload      T1027          (obfuscated payload)
//	shell-container-escape     T1611          (escape to host)
//	shell-cloud-cred-theft     T1552.005      (cloud instance metadata creds)
//	shell-local-exploit        T1068          (kernel/local privesc exploit)
//	shell-data-staged          T1560.001      (archive collected data)
//	shell-exfil-channel        T1048          (exfil over alt channel)
//	shell-decode-pipe-exec     T1140          (decode + pipe to shell)
//	shell-destruction          T1485 / T1486  (data destruction / encryption)
func scanAnomalies(line string) []string {
	low := strings.ToLower(line)
	var out []string
	add := func(m string) {
		for _, e := range out {
			if e == m {
				return
			}
		}
		out = append(out, m)
	}

	// Reverse-shell patterns.
	switch {
	case strings.Contains(low, "bash -i"),
		strings.Contains(low, "sh -i"),
		strings.Contains(low, "/dev/tcp/"),
		strings.Contains(low, "mkfifo"),
		strings.Contains(low, "ncat -e"),
		strings.Contains(low, "nc -e"),
		strings.Contains(low, "socat exec"),
		strings.Contains(low, "python -c") && strings.Contains(low, "socket"),
		strings.Contains(low, "perl -e") && strings.Contains(low, "socket"):
		add("shell-reverse-shell")
	}

	// Tool download / ingress.
	if strings.HasPrefix(low, "wget ") || strings.HasPrefix(low, "curl ") ||
		strings.Contains(low, " wget ") || strings.Contains(low, " curl ") ||
		strings.Contains(low, "tftp -g") {
		add("shell-download-tool")
	}

	// SSH-key persistence.
	if strings.Contains(low, "authorized_keys") && (strings.Contains(low, ">>") ||
		strings.Contains(low, "echo") || strings.Contains(low, "cat >")) {
		add("shell-persistence-ssh-key")
	}

	// Cron / systemd persistence.
	if strings.Contains(low, "crontab -") && strings.Contains(low, "*") {
		add("shell-persistence-cron")
	}
	if strings.Contains(low, "/etc/cron.") || strings.Contains(low, "/var/spool/cron/") {
		add("shell-persistence-cron")
	}
	if strings.Contains(low, "systemctl enable") || strings.Contains(low, "/etc/systemd/system/") {
		add("shell-persistence-systemd")
	}

	// Credential file access.
	if strings.Contains(low, "/etc/shadow") {
		add("shell-shadow-read")
	}
	if strings.Contains(low, "/etc/passwd") && !strings.Contains(low, "cat /etc/passwd") {
		// `cat /etc/passwd` is the recon-101 thing every scanner
		// does; that's normal. But "cp /etc/passwd ..." or
		// "echo ... >> /etc/passwd" is genuine persistence.
		add("shell-passwd-write")
	} else if strings.HasPrefix(low, "cat /etc/passwd") || strings.HasPrefix(low, "head /etc/passwd") {
		add("shell-passwd-read")
	}
	if strings.Contains(low, "/.aws/credentials") || strings.Contains(low, "/.docker/config.json") ||
		strings.Contains(low, "/.kube/config") || strings.Contains(low, "/.netrc") {
		add("shell-creds-file-access")
	}
	// Planted-loot access (T1552 / credential-access): a read of one of the
	// seeded honeytoken files is high-signal — nothing benign reads them. The
	// read-command + loot-path test is shared with the Run loop's canary-token
	// recording via lootReadLine, so the anomaly marker and the served-token
	// signal can never drift apart.
	if lootReadLine(low) {
		add("shell-loot-accessed")
	}

	// Privilege escalation.
	if strings.Contains(low, "chmod") && (strings.Contains(low, "+s") || strings.Contains(low, "4755") || strings.Contains(low, "4777")) {
		add("shell-priv-esc-suid")
	}
	if strings.Contains(low, "sudo ") || strings.HasPrefix(low, "sudo ") {
		add("shell-priv-esc-sudo")
	}
	if strings.Contains(low, "/etc/sudoers") {
		add("shell-priv-esc-sudo")
	}

	// Defense evasion.
	if strings.Contains(low, "history -c") || strings.Contains(low, "rm -rf ~/.bash_history") ||
		strings.Contains(low, "unset histfile") || strings.Contains(low, "histfile=/dev/null") {
		add("shell-defense-evade-history")
	}
	// Any rm + /var/log/ in the same line is a log-clean attempt
	// (we don't care about the flag soup in between).
	if (strings.Contains(low, "/var/log/") || strings.Contains(low, "/var/log ")) &&
		(strings.Contains(low, "rm ") || strings.HasPrefix(low, "rm ") ||
			strings.Contains(low, "truncate") || strings.Contains(low, "shred ") ||
			strings.Contains(low, ">/var/log/") || strings.Contains(low, "> /var/log/")) {
		add("shell-defense-evade-logclean")
	}
	if strings.Contains(low, "iptables -f") || strings.Contains(low, "iptables -p input accept") ||
		strings.Contains(low, "ufw disable") || strings.Contains(low, "systemctl stop firewalld") ||
		strings.Contains(low, "setenforce 0") || strings.Contains(low, "systemctl disable apparmor") {
		add("shell-disable-fw")
	}

	// Living-off-the-land binaries.
	if strings.Contains(low, "openssl s_client -connect") ||
		(strings.Contains(low, "awk ") && strings.Contains(low, "/inet/tcp/")) ||
		strings.Contains(low, "lolbas") {
		add("shell-living-off-the-land")
	}

	// Crypto-miners.
	if strings.Contains(low, "xmrig") || strings.Contains(low, "minerd") ||
		strings.Contains(low, "stratum+tcp") || strings.Contains(low, "kdevtmpfsi") ||
		strings.Contains(low, "kinsing") {
		add("shell-coin-miner")
	}

	// Network reconnaissance from inside the shell.
	if strings.HasPrefix(low, "nmap ") || strings.Contains(low, "masscan ") ||
		strings.HasPrefix(low, "arp-scan ") || strings.HasPrefix(low, "rustscan ") {
		add("shell-network-recon")
	}

	// ---- Windows / PowerShell TTPs ----

	// PowerShell download-cradle / fileless execution (T1059.001 + T1105).
	if strings.Contains(low, "downloadstring") || strings.Contains(low, "downloadfile") ||
		strings.Contains(low, "net.webclient") || strings.Contains(low, "invoke-webrequest") ||
		strings.Contains(low, "start-bitstransfer") ||
		((strings.Contains(low, "iex ") || strings.Contains(low, "invoke-expression")) &&
			(strings.Contains(low, "http") || strings.Contains(low, "(new-object"))) {
		add("shell-ps-download-exec")
	}
	// Encoded PowerShell command (T1027 / T1059.001).
	if strings.Contains(low, "-encodedcommand") || strings.Contains(low, "-enc ") ||
		strings.Contains(low, "frombase64string") || strings.Contains(low, "-e jab") {
		add("shell-ps-encoded")
	}
	// Credential dumping (T1003): LSASS / SAM / NTDS / mimikatz.
	if strings.Contains(low, "mimikatz") || strings.Contains(low, "sekurlsa") ||
		strings.Contains(low, "invoke-mimikatz") || strings.Contains(low, "comsvcs.dll, minidump") ||
		strings.Contains(low, "lsass") || strings.Contains(low, "ntds.dit") ||
		(strings.Contains(low, "reg save") && (strings.Contains(low, "hklm\\sam") || strings.Contains(low, "hklm\\system"))) {
		add("shell-credential-dump")
	}
	// Active Directory enumeration (T1087.002 / T1018 / T1482).
	if strings.Contains(low, "get-aduser") || strings.Contains(low, "get-adcomputer") ||
		strings.Contains(low, "get-addomain") || strings.Contains(low, "get-adgroupmember") ||
		strings.Contains(low, "nltest") || strings.Contains(low, "dsquery") ||
		strings.Contains(low, "net group \"domain admins\"") || strings.Contains(low, "adsisearcher") {
		add("shell-ad-recon")
	}
	// Defender / AMSI tamper (T1562.001).
	if strings.Contains(low, "set-mppreference -disable") || strings.Contains(low, "add-mppreference -exclusionpath") ||
		strings.Contains(low, "amsiutils") || strings.Contains(low, "amsiinitfailed") ||
		strings.Contains(low, "sc stop windefend") || strings.Contains(low, "uninstall-windowsfeature windows-defender") {
		add("shell-defender-tamper")
	}
	// Windows persistence: registry Run key / scheduled task / service (T1547.001 / T1053.005 / T1543.003).
	if (strings.Contains(low, "reg add") && strings.Contains(low, "currentversion\\run")) ||
		strings.Contains(low, "schtasks /create") || strings.Contains(low, "new-scheduledtask") ||
		(strings.Contains(low, "new-service") || strings.Contains(low, "sc create")) {
		add("shell-persistence-windows")
	}

	// Container / namespace escape (T1611). Mounting the host disk,
	// breaking out via the docker socket, the release_agent cgroup trick,
	// or nsenter into PID 1's namespaces.
	if strings.Contains(low, "/var/run/docker.sock") ||
		strings.Contains(low, "release_agent") ||
		(strings.Contains(low, "nsenter") && strings.Contains(low, "-t 1")) ||
		(strings.Contains(low, "mount") && strings.Contains(low, "/dev/sda")) ||
		strings.Contains(low, "docker run") && strings.Contains(low, "-v /:/") ||
		strings.Contains(low, "chroot /host") {
		add("shell-container-escape")
	}

	// Cloud CLI credential / metadata theft from inside the shell (T1552.005).
	if strings.Contains(low, "169.254.169.254") ||
		strings.Contains(low, "aws sts get-caller-identity") ||
		strings.Contains(low, "aws s3 ") || strings.Contains(low, "aws secretsmanager") ||
		strings.Contains(low, "gcloud auth") || strings.Contains(low, "az account get-access-token") ||
		(strings.Contains(low, "kubectl") && strings.Contains(low, "secret")) {
		add("shell-cloud-cred-theft")
	}

	// Kernel / local privesc exploit binaries (T1068). "fragnesia" is the
	// CVE-2026-46300 Linux-kernel XFRM privesc commonly chained behind a web
	// RCE such as PHP2Shell to reach root.
	if strings.Contains(low, "dirtypipe") || strings.Contains(low, "dirtycow") ||
		strings.Contains(low, "pwnkit") || strings.Contains(low, "/tmp/exploit") ||
		strings.Contains(low, "linpeas") || strings.Contains(low, "linenum") ||
		strings.Contains(low, "fragnesia") {
		add("shell-local-exploit")
	}

	// Data staging into an archive (T1560.001) — the pre-exfil bundle step.
	if (strings.Contains(low, "tar ") && (strings.Contains(low, "czf") || strings.Contains(low, "-cf"))) ||
		strings.Contains(low, "zip -r") || strings.Contains(low, "7z a ") ||
		(strings.Contains(low, "gpg") && strings.Contains(low, "--encrypt")) {
		add("shell-data-staged")
	}

	// Exfiltration over an alternative channel (T1048) — piping data out via
	// curl/scp/nc to an external host.
	if (strings.Contains(low, "curl") && (strings.Contains(low, "-t ") || strings.Contains(low, "--data") || strings.Contains(low, "-f "))) ||
		strings.Contains(low, "scp ") || strings.Contains(low, "rsync ") && strings.Contains(low, "@") ||
		(strings.Contains(low, "nc ") && strings.Contains(low, "< ")) {
		add("shell-exfil-channel")
	}

	// Defense evasion via decode-and-pipe-to-shell (T1140) — the
	// base64 -d | bash / xxd -r cradle.
	if (strings.Contains(low, "base64 -d") || strings.Contains(low, "base64 --decode") ||
		strings.Contains(low, "xxd -r") || strings.Contains(low, "openssl enc -d")) &&
		(strings.Contains(low, "|sh") || strings.Contains(low, "| sh") ||
			strings.Contains(low, "|bash") || strings.Contains(low, "| bash")) {
		add("shell-decode-pipe-exec")
	}

	// Ransomware-style mass encryption / destruction (T1486 / T1485).
	if (strings.Contains(low, "openssl enc") && strings.Contains(low, "-aes") && strings.Contains(low, "find ")) ||
		strings.Contains(low, "dd if=/dev/zero of=/dev/sda") ||
		strings.Contains(low, "dd if=/dev/urandom of=/") ||
		strings.Contains(low, "rm -rf /") || strings.Contains(low, "rm -rf --no-preserve-root") ||
		(strings.Contains(low, ".encrypted") && strings.Contains(low, "find ")) ||
		strings.Contains(low, "mkfs.") && strings.Contains(low, "/dev/sd") {
		add("shell-destruction")
	}

	// Encoded payloads — long base64 / hex / url-encoded blobs in a
	// single line. We don't decode, just flag presence of an obvious
	// blob.
	if blobLooksEncoded(line) {
		add("shell-encoded-payload")
	}
	return out
}

// blobLooksEncoded reports whether the line contains a >=64-character
// run of base64-alphabet characters (a typical encoded-shellcode
// shape). We only count the longest run so a one-word command can't
// false-trigger on a long path.
func blobLooksEncoded(s string) bool {
	const minLen = 64
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z'),
			(c >= 'a' && c <= 'z'),
			(c >= '0' && c <= '9'),
			c == '+', c == '/', c == '=':
			run++
			if run >= minLen {
				return true
			}
		default:
			run = 0
		}
	}
	return false
}

// harvestURLs extracts http(s):// URLs from a command line (wget/curl ingress
// tool transfer, pipe-to-shell, exfil targets) so the caller can surface them
// as IOCs. Bounded, dependency-free; trims common trailing shell punctuation.
func harvestURLs(line string) []string {
	var out []string
	low := line
	for {
		i := indexScheme(low)
		if i < 0 {
			break
		}
		rest := low[i:]
		// URL ends at the first whitespace, quote, or shell metacharacter.
		end := len(rest)
		for j := 0; j < len(rest); j++ {
			c := rest[j]
			if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`' ||
				c == '|' || c == ';' || c == '>' || c == '<' || c == ')' || c == '(' {
				end = j
				break
			}
		}
		u := strings.TrimRight(rest[:end], ".,)]}'\"")
		if len(u) > len("https://") {
			out = append(out, u)
			if len(out) >= 16 {
				break
			}
		}
		low = rest[end:]
	}
	return out
}

// indexScheme returns the index of the next "http://" or "https://" (case-
// insensitive) in s, or -1.
func indexScheme(s string) int {
	ls := strings.ToLower(s)
	h := strings.Index(ls, "http://")
	hs := strings.Index(ls, "https://")
	switch {
	case h < 0:
		return hs
	case hs < 0:
		return h
	case h < hs:
		return h
	default:
		return hs
	}
}
