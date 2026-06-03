package luaengine

import "testing"

// Behavior checks for the 25 appliance / MFT / CMS / monitoring personas added
// in the fifth Lua expansion: each flags its signature probe + answers.
func TestNewScripts9CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"vmware-esxi.lua", "GET /sdk HTTP/1.1\r\nHost: x\r\n\r\n", "esxi-soap-sdk-probe"},
		{"vmware-nsx.lua", "GET /policy/api/v1/infra HTTP/1.1\r\nHost: x\r\n\r\n", "nsx-api-probe"},
		{"fortimanager.lua", "POST /jsonrpc HTTP/1.1\r\nHost: x\r\n\r\n", "fortimanager-cve-2024-47575-probe"},
		{"checkpoint-gaia.lua", "POST /clients/MIL HTTP/1.1\r\nHost: x\r\n\r\n", "checkpoint-cve-2024-24919-probe"},
		{"sophos-firewall.lua", "GET /userportal/webpages/myaccount HTTP/1.1\r\nHost: x\r\n\r\n", "sophos-cve-2022-1040-probe"},
		{"cisco-ise.lua", "GET /ers/config/endpoint HTTP/1.1\r\nHost: x\r\n\r\n", "cisco-ise-api-probe"},
		{"ruckus-smartzone.lua", "GET /wsg/api/scg/session HTTP/1.1\r\nHost: x\r\n\r\n", "ruckus-api-probe"},
		{"whatsup-gold.lua", "GET /NmAPI/Recurring/GetFileWithoutZip HTTP/1.1\r\nHost: x\r\n\r\n", "whatsupgold-cve-2024-4885-probe"},
		{"goanywhere.lua", "GET /InitialAccountSetup.xhtml HTTP/1.1\r\nHost: x\r\n\r\n", "goanywhere-cve-2024-0204-probe"},
		{"crushftp.lua", "GET /WebInterface/function/?command=zip HTTP/1.1\r\nHost: x\r\n\r\n", "crushftp-cve-2024-4040-probe"},
		{"serv-u.lua", "GET /?InternalDir=%2f..%2f..%2f&InternalFile=x HTTP/1.1\r\nHost: x\r\n\r\n", "servu-cve-2024-28995-probe"},
		{"horde.lua", "GET /login.php HTTP/1.1\r\nHost: x\r\n\r\n", "horde-login-probe"},
		{"squirrelmail.lua", "GET /src/login.php HTTP/1.1\r\nHost: x\r\n\r\n", "squirrelmail-login-probe"},
		{"magento.lua", "GET /rest/V1/guest-carts/1/estimate-shipping-methods HTTP/1.1\r\nHost: x\r\n\r\n", "magento-cve-2024-34102-probe"},
		{"drupal.lua", "POST /node?_format=hal_json HTTP/1.1\r\nHost: x\r\n\r\n", "drupal-cve-2019-6340-probe"},
		{"typo3.lua", "GET /typo3/install.php HTTP/1.1\r\nHost: x\r\n\r\n", "typo3-installtool-probe"},
		{"mediawiki.lua", "GET /api.php?action=query HTTP/1.1\r\nHost: x\r\n\r\n", "mediawiki-api-probe"},
		{"redmine.lua", "GET /issues HTTP/1.1\r\nHost: x\r\n\r\n", "redmine-probe"},
		{"centreon.lua", "GET /centreon/api/latest/monitoring HTTP/1.1\r\nHost: x\r\n\r\n", "centreon-api-probe"},
		{"rundeck.lua", "POST /api/47/run/command HTTP/1.1\r\nHost: x\r\n\r\n", "rundeck-job-exec-probe"},
		{"awx.lua", "GET /api/v2/job_templates/ HTTP/1.1\r\nHost: x\r\n\r\n", "awx-api-probe"},
		{"netbox.lua", "GET /api/secrets/secrets/ HTTP/1.1\r\nHost: x\r\n\r\n", "netbox-api-probe"},
		{"phpipam.lua", "GET /api/app/subnets/ HTTP/1.1\r\nHost: x\r\n\r\n", "phpipam-api-probe"},
		{"dolibarr.lua", "POST /index.php HTTP/1.1\r\nContent-Length: 11\r\n\r\n<?php die()", "dolibarr-cve-2023-30253-probe"},
		{"cpanel.lua", "GET /login/?goto_uri=%2f HTTP/1.1\r\nHost: x\r\n\r\n", "cpanel-login-probe"},
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
