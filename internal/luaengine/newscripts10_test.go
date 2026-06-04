package luaengine

import "testing"

// Behavior checks for the 20 chat / CI / data-platform / panel personas added in
// the sixth Lua expansion: each flags its signature probe and answers.
func TestNewScripts10CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"mattermost.lua", "GET /api/v4/users HTTP/1.1\r\nHost: x\r\n\r\n", "mattermost-api-probe"},
		{"rocketchat.lua", "POST /api/v1/login HTTP/1.1\r\nHost: x\r\n\r\n", "rocketchat-api-probe"},
		{"zeppelin.lua", "GET /api/interpreter/setting HTTP/1.1\r\nHost: x\r\n\r\n", "zeppelin-interpreter-probe"},
		{"saltstack.lua", "POST /run HTTP/1.1\r\nHost: x\r\n\r\n", "salt-cve-2020-11651-probe"},
		{"dolphinscheduler.lua", "GET /dolphinscheduler/ui/ HTTP/1.1\r\nHost: x\r\n\r\n", "dolphinscheduler-probe"},
		{"apisix.lua", "GET /apisix/admin/routes HTTP/1.1\r\nHost: x\r\n\r\n", "apisix-admin-api-probe"},
		{"moodle.lua", "GET /login/index.php HTTP/1.1\r\nHost: x\r\n\r\n", "moodle-login-probe"},
		{"odoo.lua", "POST /web/login HTTP/1.1\r\nHost: x\r\n\r\n", "odoo-login-probe"},
		{"ghost.lua", "GET /ghost/api/admin/site/ HTTP/1.1\r\nHost: x\r\n\r\n", "ghost-api-probe"},
		{"code-server.lua", "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", "codeserver-probe"},
		{"uptime-kuma.lua", "GET /socket.io/?EIO=4 HTTP/1.1\r\nHost: x\r\n\r\n", "uptimekuma-probe"},
		{"netdata.lua", "GET /api/v1/info HTTP/1.1\r\nHost: x\r\n\r\n", "netdata-info-probe"},
		{"mongo-express.lua", "GET /db/admin/ HTTP/1.1\r\nHost: x\r\n\r\n", "mongoexpress-cve-2019-10758-probe"},
		{"teleport.lua", "GET /v1/webapi/ping HTTP/1.1\r\nHost: x\r\n\r\n", "teleport-webapi-probe"},
		{"vaultwarden.lua", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", "vaultwarden-admin-probe"},
		{"ispconfig.lua", "GET /login/index.php HTTP/1.1\r\nHost: x\r\n\r\n", "ispconfig-login-probe"},
		{"plesk.lua", "GET /login_up.php HTTP/1.1\r\nHost: x\r\n\r\n", "plesk-login-probe"},
		{"omada.lua", "GET /api/v2/loginStatus HTTP/1.1\r\nHost: x\r\n\r\n", "omada-api-probe"},
		{"redash.lua", "GET /api/queries HTTP/1.1\r\nHost: x\r\n\r\n", "redash-query-api-probe"},
		{"hasura.lua", "POST /v1/graphql HTTP/1.1\r\nHost: x\r\n\r\n", "hasura-graphql-probe"},
	}
	if len(cases) != 20 {
		t.Fatalf("expected 20 new personas, have %d", len(cases))
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

// A login POST must capture the submitted credentials.
func TestNewScripts10CaptureLogin(t *testing.T) {
	_, meta, _ := runScriptFile(t, "moodle.lua",
		"POST /login/index.php HTTP/1.1\r\nContent-Length: 32\r\n\r\nusername=admin&password=Passw0rd")
	if meta["auth_user"] != "admin" || meta["auth_pass"] != "Passw0rd" {
		t.Errorf("moodle login not captured: user=%v pass=%v", meta["auth_user"], meta["auth_pass"])
	}
}
