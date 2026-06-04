package archeservice

import (
	"regexp"
	"testing"
)

// Every role must yield a well-formed CPE 2.3 string (curated where a canonical
// product exists, generic otherwise).
func TestEveryRoleHasWellFormedCPE(t *testing.T) {
	re := regexp.MustCompile(`^cpe:2\.3:[hoa]:[a-z0-9._\\&-]+:[a-z0-9._\\&-]+:[^:]+(:[^:]*){7}$`)
	for _, r := range Names() {
		cpe := CPE(r)
		if !re.MatchString(cpe) {
			t.Errorf("role %q: malformed CPE %q", r, cpe)
		}
	}
	// A curated role and a generic fallback.
	if CPE("webserver") != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Errorf("webserver CPE wrong: %q", CPE("webserver"))
	}
	if got := CPE("definitely-not-a-real-role"); got != "cpe:2.3:a:generic:definitelynotarealrole:*:*:*:*:*:*:*:*" {
		t.Errorf("generic fallback wrong: %q", got)
	}
}
