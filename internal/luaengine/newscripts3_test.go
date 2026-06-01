package luaengine

import "testing"

// TestNewScripts3CaptureBehavior drives realistic input through the third batch
// of shipped scripts and asserts each service's capture flag.
func TestNewScripts3CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"wordpress.lua",
			"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: 24\r\n\r\nlog=admin&pwd=Summer2025",
			"wordpress-login-attempt"},
		{"wordpress.lua",
			"POST /xmlrpc.php HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\n<methodCall><methodName>system.multicall",
			"wordpress-xmlrpc-bruteforce"},
		{"roundcube.lua",
			"POST /?_task=login HTTP/1.1\r\nHost: x\r\nContent-Length: 26\r\n\r\n_user=bob&_pass=hunter2xyz",
			"roundcube-login-attempt"},
		{"pgadmin.lua",
			"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 18\r\n\r\nemail=a@b.c&csrf=1",
			"pgadmin-login-attempt"},
		{"splunk.lua",
			"GET /en-US/modules/messaging/C:../../../../passwd HTTP/1.1\r\nHost: x\r\n\r\n",
			"splunk-traversal-probe"},
		{"manageengine.lua",
			"POST /samlLogin/abc HTTP/1.1\r\nHost: x\r\n\r\n",
			"manageengine-saml-probe"},
		{"zimbra.lua",
			"GET /service/extension/backup/mboximport?account-name=x HTTP/1.1\r\nHost: x\r\n\r\n",
			"zimbra-mboximport-probe"},
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
