package luaengine

import "testing"

// TestNewScripts2CaptureBehavior drives realistic input through the second
// batch of shipped scripts and asserts each service's capture flag.
func TestNewScripts2CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"metabase.lua",
			"GET /api/setup/validate HTTP/1.1\r\nHost: x\r\n\r\n",
			"metabase-setup-token-abuse"},
		{"superset.lua",
			"POST /login/ HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\nusername=admin&password=admin1",
			"superset-login-attempt"},
		{"nodered.lua",
			"POST /flows HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\n[{\"type\":\"exec\",\"command\":\"id\"}]",
			"nodered-code-injection"},
		{"thinkphp.lua",
			"GET /index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array HTTP/1.1\r\nHost: x\r\n\r\n",
			"thinkphp-rce-attempt"},
		{"geoserver.lua",
			"GET /geoserver/ows?service=WFS&valueReference=exec(java.lang.Runtime.getRuntime()) HTTP/1.1\r\nHost: x\r\n\r\n",
			"geoserver-jxpath-rce"},
		{"rancher.lua",
			"GET /v3/clusters HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer token-abc\r\n\r\n",
			"rancher-cluster-enum"},
	}
	for _, c := range cases {
		anoms, _, banner := runScriptFile(t, c.name, c.input)
		if !hasFlag(anoms, c.wantFlag) {
			t.Errorf("%s: expected flag %q; anomalies=%v", c.name, c.wantFlag, anoms)
		}
		if banner == "" {
			t.Errorf("%s: expected a response banner", c.name)
		}
	}
}
