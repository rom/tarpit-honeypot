package archeservice

import "testing"

func TestLookupKnownRoles(t *testing.T) {
	for _, role := range []string{"webserver", "ftpserver", "printserver", "fileserver", "ldapserver", "adserver"} {
		svcs, ok := Lookup(role)
		if !ok || len(svcs) == 0 {
			t.Errorf("role %q did not resolve to any services", role)
		}
	}
}

func TestLookupNormalization(t *testing.T) {
	a, _ := Lookup("webserver")
	for _, variant := range []string{"WebServer", "web-server", "web_server", " WEBSERVER "} {
		b, ok := Lookup(variant)
		if !ok || len(b) != len(a) {
			t.Errorf("variant %q did not resolve like webserver", variant)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("not-a-role"); ok {
		t.Error("unknown role resolved")
	}
}

func TestNamesNonEmpty(t *testing.T) {
	if len(Names()) == 0 {
		t.Fatal("Names() empty")
	}
}

// Every role's services must declare a valid proto and a non-empty handler
// — coherence guard so a typo in the catalog is caught at test time. (The
// config package separately checks the handler names against the listener
// whitelist; this just guards the shape.)
func TestRoleServicesWellFormed(t *testing.T) {
	for _, name := range Names() {
		svcs, _ := Lookup(name)
		seen := map[string]bool{}
		for _, s := range svcs {
			if s.Proto != "tcp" && s.Proto != "udp" {
				t.Errorf("role %q service :%d has bad proto %q", name, s.Port, s.Proto)
			}
			if s.Handler == "" {
				t.Errorf("role %q service :%d has empty handler", name, s.Port)
			}
			if s.Port <= 0 || s.Port > 65535 {
				t.Errorf("role %q has out-of-range port %d", name, s.Port)
			}
			key := s.Proto + ":" + itoa(s.Port)
			if seen[key] {
				t.Errorf("role %q has duplicate %s", name, key)
			}
			seen[key] = true
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
