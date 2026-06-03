package luaengine

import "testing"

// Behavior checks for the 10 enterprise/appliance personas added in the
// protocol-coverage expansion: each must flag the high-signal probe and answer
// with a recognizable banner.
func TestNewScripts6CaptureBehavior(t *testing.T) {
	cases := []struct {
		name, input, wantFlag string
	}{
		{"tomcat-manager.lua",
			"GET /manager/html HTTP/1.1\r\nAuthorization: Basic dG9tY2F0OnRvbWNhdA==\r\n\r\n",
			"tomcat-auth-attempt"},
		{"vcenter.lua",
			"GET /ui/vropspluginui/rest/services/uploadova HTTP/1.1\r\nHost: x\r\n\r\n",
			"vcenter-cve-2021-21972-probe"},
		{"fortios-vpn.lua",
			"GET /remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession HTTP/1.1\r\nHost: x\r\n\r\n",
			"fortios-cve-2018-13379-probe"},
		{"citrix-netscaler.lua",
			"GET /vpn/../vpns/cfg/smb.conf HTTP/1.1\r\nHost: x\r\n\r\n",
			"citrix-cve-2019-19781-probe"},
		{"exchange-owa.lua",
			"GET /autodiscover/autodiscover.json?@evil.com/&Email=a HTTP/1.1\r\nHost: x\r\n\r\n",
			"exchange-proxyshell-probe"},
		{"coldfusion.lua",
			"GET /CFIDE/administrator/index.cfm HTTP/1.1\r\nHost: x\r\n\r\n",
			"coldfusion-admin-probe"},
		{"activemq.lua",
			"GET /admin/ HTTP/1.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n",
			"activemq-auth-attempt"},
		{"ivanti-ics.lua",
			"POST /api/v1/totp/user-backup-code HTTP/1.1\r\nHost: x\r\n\r\n",
			"ivanti-cve-2024-21887-probe"},
		{"dlink-hnap.lua",
			"POST /HNAP1/ HTTP/1.1\r\nSOAPAction: \"http://purenetworks.com/HNAP1/`telnetd`\"\r\n\r\n",
			"dlink-hnap-command-injection"},
		{"zyxel-firewall.lua",
			"POST /ztp/cgi-bin/handler HTTP/1.1\r\nHost: x\r\n\r\n",
			"zyxel-cve-2022-30525-probe"},
		{"solarwinds-orion.lua",
			"GET /WebResource.axd?d=abc HTTP/1.1\r\nHost: x\r\n\r\n",
			"solarwinds-cve-2020-10148-probe"},
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
