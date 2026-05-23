package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func hasAnomaly(res Result, marker string) bool {
	if res.Meta == nil {
		return false
	}
	list, _ := res.Meta["anomalies"].([]string)
	for _, m := range list {
		if m == marker {
			return true
		}
	}
	return false
}

func TestRsyncModuleList(t *testing.T) {
	res, out := roundtrip(t, rsyncH{}, "@RSYNCD: 31.0\n#list\n")
	if !strings.Contains(string(out), "@RSYNCD: 31.0") {
		t.Errorf("missing rsync greeting: %q", out)
	}
	if !hasAnomaly(res, "rsync-module-list") {
		t.Errorf("rsync-module-list not flagged: %v", res.Meta["anomalies"])
	}
}

func TestGopherSSRF(t *testing.T) {
	res, _ := roundtrip(t, gopherH{}, "GET / HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n")
	if !hasAnomaly(res, "gopher-request") {
		t.Errorf("gopher-request not flagged")
	}
	if !hasAnomaly(res, "gopher-ssrf") {
		t.Errorf("gopher-ssrf not flagged for an HTTP-smuggling selector: %v", res.Meta["anomalies"])
	}
}

func TestSocks5ConnectTarget(t *testing.T) {
	// greeting: VER=5, NMETHODS=1, METHOD=0 ; request: CONNECT 127.0.0.1:80
	in := string([]byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	res, _ := roundtrip(t, socksH{}, in)
	if res.Meta["socks_target"] != "127.0.0.1:80" {
		t.Errorf("socks_target = %v; want 127.0.0.1:80", res.Meta["socks_target"])
	}
	if res.Meta["socks_cmd"] != "CONNECT" || !hasAnomaly(res, "socks-proxy-attempt") {
		t.Errorf("socks meta wrong: %v", res.Meta)
	}
}

func TestBGPOpen(t *testing.T) {
	hdr := make([]byte, 19)
	for i := 0; i < 16; i++ {
		hdr[i] = 0xFF
	}
	// length = 19 + 10 body, type = 1 (OPEN)
	hdr[16], hdr[17], hdr[18] = 0x00, 29, 1
	body := []byte{4, 0xFD, 0xE8, 0x00, 0xB4, 10, 0, 0, 1, 0} // ver, AS=65000, hold=180, id=10.0.0.1, optlen=0
	res, _ := roundtrip(t, bgpH{}, string(hdr)+string(body))
	if res.Meta["bgp_type"] != "OPEN" || !hasAnomaly(res, "bgp-open-attempt") {
		t.Errorf("bgp meta wrong: %v", res.Meta)
	}
	if res.Meta["bgp_peer_as"] != 65000 {
		t.Errorf("bgp_peer_as = %v; want 65000", res.Meta["bgp_peer_as"])
	}
}

func TestISAKMPProbe(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[17] = 0x10 // version 1.0
	pkt[18] = 2    // main mode
	res, _ := isakmp{}.Handle(context.Background(), pkt, nil, nil, config.Listener{})
	if !hasAnomaly(res, "ike-probe") {
		t.Errorf("ike-probe not flagged: %v", res.Meta)
	}
}

func TestNetbiosDatagram(t *testing.T) {
	res, _ := netbiosDgram{}.Handle(context.Background(), []byte{0x11, 0x02}, nil, nil, config.Listener{})
	if res.Meta["nbds_msg_type"] != "DIRECT_GROUP" || !hasAnomaly(res, "netbios-datagram") {
		t.Errorf("netbios meta wrong: %v", res.Meta)
	}
}

func TestWebappVariants(t *testing.T) {
	var res Result
	res.Meta = map[string]any{}
	wp := serveWebappVariant("GET /wp-login.php HTTP/1.1", nil, "nginx", nil, &res, "wordpress")
	if !strings.Contains(wp, "loginform") || !strings.Contains(wp, "WordPress") {
		t.Errorf("wordpress variant didn't render wp-login: %q", wp)
	}
	res2 := Result{Meta: map[string]any{}}
	pma := serveWebappVariant("GET /phpmyadmin/ HTTP/1.1", nil, "nginx", nil, &res2, "phpmyadmin")
	if !strings.Contains(pma, "phpMyAdmin") {
		t.Errorf("phpmyadmin variant didn't render: %q", pma)
	}
	// A shared path (.env) still works under a variant (falls through).
	res3 := Result{Meta: map[string]any{}}
	env := serveWebappVariant("GET /.env HTTP/1.1", nil, "nginx", nil, &res3, "wordpress")
	if !hasAnomaly(res3, "webapp:secret-file-probe") {
		t.Errorf("shared .env route should still flag under a variant: %q", env)
	}
}
