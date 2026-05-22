package handler

import "testing"

func TestIsDoHRequest(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		headers []string
		payload string
		want    bool
	}{
		{"well-known path", "/dns-query", nil, "", true},
		{"path with prefix", "/dns-query", []string{"host"}, "", true},
		{"media type via accept", "/resolve", []string{"accept"}, "Accept: application/dns-message\r\n", true},
		{"media type via content-type", "/q", []string{"content-type"}, "Content-Type: application/dns-message\r\n", true},
		{"media type but no header key", "/q", nil, "application/dns-message", false},
		{"plain web request", "/index.html", []string{"accept", "user-agent"}, "Accept: text/html\r\n", false},
	}
	for _, c := range cases {
		if got := isDoHRequest(c.path, c.headers, []byte(c.payload)); got != c.want {
			t.Errorf("%s: isDoHRequest(%q,%v) = %v; want %v", c.name, c.path, c.headers, got, c.want)
		}
	}
}
