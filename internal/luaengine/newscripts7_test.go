package luaengine

import "testing"

// Behavior checks for the 10 appliance/web-framework personas added in the
// second protocol-coverage expansion: each flags its signature exploit and
// answers with a recognizable banner.
func TestNewScripts7CaptureBehavior(t *testing.T) {
	cases := []struct {
		name, input, wantFlag string
	}{
		{"paloalto-globalprotect.lua",
			"GET /ssl-vpn/hipreport.esp HTTP/1.1\r\nHost: x\r\n\r\n",
			"paloalto-globalprotect-probe"},
		{"f5-bigip.lua",
			"GET /mgmt/tm/util/bash HTTP/1.1\r\nHost: x\r\n\r\n",
			"f5-cve-2022-1388-probe"},
		{"cisco-iosxe.lua",
			"GET /webui/logoutconfirm.html?logon_hash=1 HTTP/1.1\r\nHost: x\r\n\r\n",
			"cisco-cve-2023-20198-probe"},
		{"apache-struts.lua",
			"GET /index.action HTTP/1.1\r\nHost: x\r\nContent-Type: %{(#a=1)}\r\n\r\n",
			"struts-cve-2017-5638-probe"},
		{"spring-actuator.lua",
			"GET /actuator/env HTTP/1.1\r\nHost: x\r\n\r\n",
			"spring-actuator-secrets-probe"},
		{"php-cgi.lua",
			"GET /index.php?%ad-d+allow_url_include%3d1 HTTP/1.1\r\nHost: x\r\n\r\n",
			"php-cve-2024-4577-probe"},
		{"qnap-qts.lua",
			"GET /photo/p/api/video.php HTTP/1.1\r\nHost: x\r\n\r\n",
			"qnap-cve-2022-27593-probe"},
		{"openfire.lua",
			"GET /setup/setup-/%u002e%u002e/%u002e%u002e/log.jsp HTTP/1.1\r\nHost: x\r\n\r\n",
			"openfire-cve-2023-32315-probe"},
		{"telerik-ui.lua",
			"GET /Telerik.Web.UI.WebResource.axd?type=rau HTTP/1.1\r\nHost: x\r\n\r\n",
			"telerik-cve-2017-11317-probe"},
		{"cisco-asa-webvpn.lua",
			"GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/../&filename=../1 HTTP/1.1\r\nHost: x\r\n\r\n",
			"cisco-cve-2020-3452-probe"},
	}
	for _, c := range cases {
		anoms, _, banner := runScriptFile(t, c.name, c.input)
		if !hasFlag(anoms, c.wantFlag) {
			t.Errorf("%s: expected flag %q; anomalies=%v", c.name, c.wantFlag, anoms)
		}
		if banner == "" {
			t.Errorf("%s: expected some response banner", c.name)
		}
	}
}
