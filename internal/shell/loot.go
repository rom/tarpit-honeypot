package shell

import (
	"strings"
	"sync/atomic"
)

// Planted "loot": believable but entirely fake secret-bearing files seeded into
// the fake filesystem so an attacker who lands a shell keeps digging (deeper
// engagement) and reveals intent — and so every read is a high-signal
// credential-access signal. The secret values are honeytokens: non-routable
// example hosts and placeholder secrets that execute/grant nothing.
//
// A per-deployment canary token (SetLootToken, derived from the sensor
// identity) is woven into the credential values via the {{TOK}} sentinel, so
// each sensor's loot is unique and attributable. When a loot credential file is
// read the shell records that token as "served" (Captured.ServedLootTokens);
// the sensor feeds it into the honey-credential reuse tracker, so if the
// attacker later replays the captured secret against any login-bearing service
// it fires a critical canary:token_used — turning a read of a fake file into
// live proof of compromise.

// lootToken holds the per-deployment canary woven into loot (set once at
// startup; read on the serve path). atomic so a connection can't race the set.
var lootToken atomic.Pointer[string]

// SetLootToken installs the per-deployment canary token (call once at startup,
// before listeners serve). Empty restores the static fallback.
func SetLootToken(tok string) { lootToken.Store(&tok) }

// currentLootToken returns the active canary token, or a static fallback when
// none has been set (OneShot / tests).
func currentLootToken() string {
	if p := lootToken.Load(); p != nil && *p != "" {
		return *p
	}
	return "HONEYTOKEN-decoy"
}

// lootFiles maps a fake path to its content; {{TOK}} is replaced with the
// per-deployment canary at serve time.
var lootFiles = map[string]string{
	"/root/.aws/credentials": "[default]\r\n" +
		"aws_access_key_id = AKIA-HONEYTOKEN-EXAMPLE\r\n" +
		"aws_secret_access_key = honeytoken-{{TOK}}\r\n" +
		"region = us-east-1\r\n",
	"/root/.env": "APP_ENV=production\r\n" +
		"DB_HOST=10.10.0.12\r\nDB_NAME=appdb\r\nDB_USER=appadmin\r\nDB_PASSWORD=Pr0d-{{TOK}}\r\n" +
		"REDIS_URL=redis://10.10.0.13:6379\r\n" +
		"STRIPE_SECRET_KEY=sk_live_HONEYTOKEN-{{TOK}}\r\n" +
		"JWT_SECRET=honeytoken-{{TOK}}\r\n",
	"/var/www/html/wp-config.php": "<?php\r\n" +
		"define('DB_NAME', 'wordpress');\r\n" +
		"define('DB_USER', 'wpadmin');\r\n" +
		"define('DB_PASSWORD', 'Wp-{{TOK}}');\r\n" +
		"define('DB_HOST', '10.10.0.12');\r\n" +
		"define('AUTH_KEY', 'honeytoken-{{TOK}}');\r\n",
	"/root/backup.sql": "-- MySQL dump 10.13\r\n" +
		"INSERT INTO users (id,email,pass_hash) VALUES\r\n" +
		"(1,'admin@corp.example','$2y$10$EXAMPLEhoneytokenHashAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),\r\n" +
		"(2,'dbadmin@corp.example','$2y$10$EXAMPLEhoneytokenHashBBBBBBBBBBBBBBBBBBBBBBBBBBBB');\r\n",
	"/root/notes.txt": "infra notes\r\n-----------\r\n" +
		"prod db   : 10.10.0.12  (dbadmin / Pr0d-{{TOK}})\r\n" +
		"jump host : 10.10.0.2   (ops / see password manager)\r\n" +
		"vpn portal: https://vpn.corp.example/  (admin / Vpn-{{TOK}})\r\n",
	// A decoy key: the PEM markers an attacker looks for, but the body is an
	// obvious placeholder (not a valid key) so it won't match a private-key
	// scanner.
	"/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" +
		"HONEYTOKEN-decoy-not-a-real-private-key-do-not-use\r\n" +
		"-----END OPENSSH PRIVATE KEY-----\r\n",
	"/home/admin/.bash_history": "ls -la\r\ncd /opt/app\r\n" +
		"mysql -h 10.10.0.12 -u dbadmin -p'Pr0d-{{TOK}}' appdb\r\n" +
		"scp deploy@10.10.0.2:/srv/release.tgz .\r\nsudo systemctl restart app\r\n",
}

// lootCat returns the content for a planted loot path (with the per-deployment
// token substituted), if any.
func lootCat(path string) (string, bool) {
	c, ok := lootFiles[path]
	if !ok {
		return "", false
	}
	return strings.ReplaceAll(c, "{{TOK}}", currentLootToken()), true
}

// lootIn returns the base filenames of loot seeded directly in dir (no trailing
// slash), so `ls <dir>` shows them alongside the static listing.
func lootIn(dir string) []string {
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "/"
	}
	var out []string
	for p := range lootFiles {
		i := strings.LastIndexByte(p, '/')
		if p[:i] == dir || (dir == "/" && i == 0) {
			out = append(out, p[i+1:])
		}
	}
	return out
}

// isLootPath reports whether path is a planted loot file.
func isLootPath(path string) bool {
	_, ok := lootFiles[path]
	return ok
}

// lootReadLine reports whether a (lower-cased) command line reads a planted
// credential loot file — the signal that the per-deployment canary was served.
// Shared by the anomaly scanner (shell-loot-accessed) and the Run loop (token
// recording).
func lootReadLine(low string) bool {
	readers := strings.HasPrefix(low, "cat ") || strings.HasPrefix(low, "head ") ||
		strings.HasPrefix(low, "tail ") || strings.HasPrefix(low, "less ") ||
		strings.HasPrefix(low, "more ") || strings.HasPrefix(low, "grep ") ||
		strings.Contains(low, "scp ") || strings.Contains(low, "curl ") ||
		strings.Contains(low, "nc ")
	if !readers {
		return false
	}
	for _, lp := range []string{"/.aws/credentials", "/.env", "wp-config.php", "backup.sql",
		"/root/notes.txt", "/.ssh/id_rsa", "/home/admin/.bash_history"} {
		if strings.Contains(low, lp) {
			return true
		}
	}
	return false
}
