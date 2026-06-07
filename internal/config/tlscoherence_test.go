package config

import (
	"strings"
	"testing"
)

func TestTLSCoherenceWarnings(t *testing.T) {
	cases := []struct {
		name      string
		domain    string
		tlsDomain string
		httpsHost string // an https.hosts override on a single listener (optional)
		wantWarn  bool
	}{
		{name: "both unset", wantWarn: false},
		{name: "no domain ignores tls", tlsDomain: "acme.test", wantWarn: false},
		{name: "tls inherits domain", domain: "corp.example.com", wantWarn: false},
		{name: "tls equals domain", domain: "corp.example.com", tlsDomain: "corp.example.com", wantWarn: false},
		{name: "tls subdomain of domain", domain: "example.com", tlsDomain: "mail.example.com", wantWarn: false},
		{name: "domain subdomain of tls", domain: "mail.example.com", tlsDomain: "example.com", wantWarn: false},
		{name: "same registrable", domain: "a.example.com", tlsDomain: "b.example.com", wantWarn: false},
		{name: "case/dot insensitive", domain: "Corp.Example.com", tlsDomain: ".corp.example.COM", wantWarn: false},
		{name: "different registrable", domain: "corp.example.com", tlsDomain: "acme.test", wantWarn: true},
		{name: "off-domain https host", domain: "corp.example.com", httpsHost: "intranet.evil.test", wantWarn: true},
		{name: "on-domain https host", domain: "corp.example.com", httpsHost: "www.corp.example.com", wantWarn: false},
		{name: "ip https host ignored", domain: "corp.example.com", httpsHost: "10.0.0.5", wantWarn: false},
		{name: "localhost https host ignored", domain: "corp.example.com", httpsHost: "localhost", wantWarn: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{}
			c.Sensor.Domain = tc.domain
			c.Sensor.TLSDomain = tc.tlsDomain
			if tc.httpsHost != "" {
				l := Listener{ID: "web"}
				l.HTTPS.Hosts = []string{tc.httpsHost}
				c.Listeners = append(c.Listeners, l)
			}
			got := c.TLSCoherenceWarnings()
			if (len(got) > 0) != tc.wantWarn {
				t.Errorf("warnings=%v; wantWarn=%v", got, tc.wantWarn)
			}
			// When we flag a mismatch, the message should name the offending value.
			if tc.wantWarn && len(got) > 0 {
				joined := strings.Join(got, " ")
				if tc.tlsDomain != "" && !strings.Contains(joined, tc.tlsDomain) &&
					tc.httpsHost == "" {
					t.Errorf("warning %q should mention tls_domain %q", joined, tc.tlsDomain)
				}
			}
		})
	}
}
