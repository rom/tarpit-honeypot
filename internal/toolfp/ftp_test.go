package toolfp

import "testing"

func TestIdentifyFTP(t *testing.T) {
	cases := []struct {
		user, pass, want string
	}{
		{"anonymous", "IEUser@", "nmap"},
		{"anonymous", "mozilla@example.com", "firefox"},
		{"anonymous", "chrome@nowhere", "chrome"},
		{"zgrab", "x", "zgrab"},
		{"admin", "hydra", "hydra"},
	}
	for _, c := range cases {
		got := IdentifyFTP(c.user, c.pass)
		if len(got) == 0 || got[0] != c.want {
			t.Errorf("IdentifyFTP(%q,%q) = %v, want %q", c.user, c.pass, got, c.want)
		}
	}
	if got := IdentifyFTP("bob", "s3cret"); len(got) != 0 {
		t.Errorf("benign creds should fingerprint nothing, got %v", got)
	}
}
