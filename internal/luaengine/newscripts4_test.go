package luaengine

import "testing"

// TestNewScripts4CaptureBehavior drives the 2.8 batch of shipped scripts and
// asserts each captures + flags the expected abuse.
func TestNewScripts4CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"squid.lua",
			"CONNECT smtp.victim.example:25 HTTP/1.1\r\nHost: smtp.victim.example:25\r\n\r\n",
			"open-proxy-connect"},
		{"squid.lua",
			"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"open-proxy-request"},
		{"stomp.lua",
			"CONNECT\naccept-version:1.2\nlogin:admin\npasscode:s3cret\n\n\x00",
			"stomp-connect"},
		{"tor-control.lua",
			"AUTHENTICATE \"hunter2\"\r\nQUIT\r\n",
			"tor-control-auth"},
	}
	for _, c := range cases {
		anoms, meta, banner := runScriptFile(t, c.name, c.input)
		if !hasFlag(anoms, c.wantFlag) {
			t.Errorf("%s: expected flag %q; anomalies=%v", c.name, c.wantFlag, anoms)
		}
		if banner == "" {
			t.Errorf("%s: expected a response banner", c.name)
		}
		_ = meta
	}
	// stomp + tor-control capture credentials into auth_user/auth_pass.
	_, meta, _ := runScriptFile(t, "stomp.lua", "CONNECT\nlogin:bob\npasscode:pw123\n\n\x00")
	if meta["auth_user"] != "bob" || meta["auth_pass"] != "pw123" {
		t.Errorf("stomp creds not captured: %v", meta)
	}
	_, meta2, _ := runScriptFile(t, "tor-control.lua", "AUTHENTICATE topsecret\r\n")
	if meta2["auth_pass"] != "topsecret" {
		t.Errorf("tor-control pass not captured: %v", meta2["auth_pass"])
	}
}
