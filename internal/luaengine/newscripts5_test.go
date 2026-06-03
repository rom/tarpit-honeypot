package luaengine

import (
	"fmt"
	"testing"
)

// post builds a minimal HTTP POST request with a correct Content-Length.
func post(path, body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", path, len(body), body)
}
func get(path string) string { return "GET " + path + " HTTP/1.1\r\nHost: x\r\n\r\n" }

// TestNewScripts5CaptureBehavior drives the 2.8 batch of 15 new service
// personas and asserts each flags its expected probe / login.
func TestNewScripts5CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"webmin.lua", post("/session_login.cgi", "user=root&pass=x"), "webmin-login-attempt"},
		{"webmin.lua", get("/password_change.cgi"), "webmin-passwd-rce-probe"},
		{"cacti.lua", post("/index.php", "login_username=admin&login_password=x"), "cacti-login-attempt"},
		{"proxmox.lua", post("/api2/json/access/ticket", "username=root@pam&password=x"), "proxmox-login-attempt"},
		{"openwrt-luci.lua", post("/cgi-bin/luci", "luci_username=root&luci_password=x"), "luci-login-attempt"},
		{"pihole.lua", post("/admin/index.php", "pw=secret"), "pihole-login-attempt"},
		{"weblogic.lua", get("/wls-wsat/CoordinatorPortType"), "weblogic-wlswsat-rce-probe"},
		{"jboss.lua", get("/jmx-console/"), "jboss-jmx-console-probe"},
		{"jira.lua", get("/secure/ContactAdministrators!default.jspa"), "jira-ssti-probe"},
		{"confluence.lua", get("/template/aui/text-inline.vm"), "confluence-cve-2023-22527-probe"},
		{"sharepoint.lua", get("/_layouts/15/ToolPane.aspx?DisplayMode=Edit"), "sharepoint-toolpane-rce-probe"},
		{"nextcloud.lua", post("/login", "user=admin&password=x"), "nextcloud-login-attempt"},
		{"hikvision.lua", get("/SDK/webLanguage"), "hikvision-cve-2021-36260-probe"},
		{"mikrotik.lua", post("/jsproxy", "name=admin&password=x"), "mikrotik-login-attempt"},
		{"sonicwall.lua", get("/cgi-bin/jarrewrite.sh"), "sonicwall-cve-2021-20038-probe"},
		{"teamcity.lua", get("/app/rest/users/id:1/tokens/x;.jsp"), "teamcity-cve-2024-27198-probe"},
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
	// A couple capture the credential into auth_user/auth_pass (→ /captures).
	_, meta, _ := runScriptFile(t, "webmin.lua", post("/session_login.cgi", "user=root&pass=hunter2"))
	if meta["auth_user"] != "root" || meta["auth_pass"] != "hunter2" {
		t.Errorf("webmin creds not captured: %v", meta)
	}
	_, meta2, _ := runScriptFile(t, "proxmox.lua", post("/api2/json/access/ticket", "username=admin@pve&password=pw"))
	if meta2["auth_user"] != "admin@pve" {
		t.Errorf("proxmox user not captured: %v", meta2["auth_user"])
	}
}
