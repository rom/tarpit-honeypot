package shell

import "strings"

// Planted "loot": believable but entirely fake secret-bearing files seeded into
// the fake filesystem so an attacker who lands a shell keeps digging (deeper
// engagement) and reveals intent — and so every read is a high-signal
// credential-access signal. The values are honeytokens: non-routable example
// hosts (RFC 5737 / RFC 1918), obviously-example keys, and placeholder
// passwords. They execute nothing and grant nothing; an operator can register
// the exact strings with the canary / token-tracking system so that if one is
// ever replayed elsewhere it trips. Reads are flagged shell-loot-accessed
// (plus the existing shell-creds-file-access for the credential files).
var lootFiles = map[string]string{
	// Values are deliberately BROKEN so they can't match a real provider's
	// secret-scanning regex (no valid AKIA…/sk_live_… shapes) — these are
	// decoys, and an operator doesn't want real-looking secrets in their repo
	// or logs either. They still read as "creds" to an attacker.
	"/root/.aws/credentials": "[default]\r\n" +
		"aws_access_key_id = AKIA-HONEYTOKEN-EXAMPLE\r\n" +
		"aws_secret_access_key = honeytoken-not-a-real-aws-secret\r\n" +
		"region = us-east-1\r\n",
	"/root/.env": "APP_ENV=production\r\n" +
		"DB_HOST=10.10.0.12\r\nDB_NAME=appdb\r\nDB_USER=appadmin\r\nDB_PASSWORD=S3cr3t-Pr0d-DB-Pw!\r\n" +
		"REDIS_URL=redis://10.10.0.13:6379\r\n" +
		"STRIPE_SECRET_KEY=sk_live_HONEYTOKEN-not-a-real-key\r\n" +
		"JWT_SECRET=honeytoken-not-a-real-jwt-secret\r\n",
	"/var/www/html/wp-config.php": "<?php\r\n" +
		"define('DB_NAME', 'wordpress');\r\n" +
		"define('DB_USER', 'wpadmin');\r\n" +
		"define('DB_PASSWORD', 'Wp-Pr0d-Pass-2026!');\r\n" +
		"define('DB_HOST', '10.10.0.12');\r\n" +
		"define('AUTH_KEY', 'example-honeytoken-auth-key');\r\n",
	"/root/backup.sql": "-- MySQL dump 10.13\r\n" +
		"INSERT INTO users (id,email,pass_hash) VALUES\r\n" +
		"(1,'admin@corp.example','$2y$10$EXAMPLEhoneytokenHashAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),\r\n" +
		"(2,'dbadmin@corp.example','$2y$10$EXAMPLEhoneytokenHashBBBBBBBBBBBBBBBBBBBBBBBBBBBB');\r\n",
	"/root/notes.txt": "infra notes\r\n-----------\r\n" +
		"prod db   : 10.10.0.12  (dbadmin / S3cr3t-Pr0d-DB-Pw!)\r\n" +
		"jump host : 10.10.0.2   (ops / see password manager)\r\n" +
		"vpn portal: https://vpn.corp.example/  (admin / Vpn-Admin-2026)\r\n",
	// A decoy key: the PEM markers an attacker looks for, but the body is an
	// obvious placeholder (not a valid key) so it won't match a private-key
	// scanner.
	"/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" +
		"HONEYTOKEN-decoy-not-a-real-private-key-do-not-use\r\n" +
		"-----END OPENSSH PRIVATE KEY-----\r\n",
	"/home/admin/.bash_history": "ls -la\r\ncd /opt/app\r\n" +
		"mysql -h 10.10.0.12 -u dbadmin -p'S3cr3t-Pr0d-DB-Pw!' appdb\r\n" +
		"scp deploy@10.10.0.2:/srv/release.tgz .\r\nsudo systemctl restart app\r\n",
}

// lootCat returns the content for a planted loot path, if any.
func lootCat(path string) (string, bool) {
	c, ok := lootFiles[path]
	return c, ok
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

// isLootPath reports whether path is a planted loot file (used to flag reads).
func isLootPath(path string) bool {
	_, ok := lootFiles[path]
	return ok
}
