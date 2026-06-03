package luaengine

import "testing"

// Behavior checks for the 26 enterprise/appliance/AI-infra personas added in the
// fourth Lua expansion: each flags its signature probe + answers with a banner.
func TestNewScripts8CaptureBehavior(t *testing.T) {
	cases := []struct{ name, input, wantFlag string }{
		{"wso2.lua", "POST /fileupload/toolsAny HTTP/1.1\r\nHost: x\r\n\r\n", "wso2-cve-2022-29464-probe"},
		{"apache-ofbiz.lua", "GET /webtools/control/main?requirePasswordChange=Y HTTP/1.1\r\nHost: x\r\n\r\n", "ofbiz-cve-2024-27348-probe"},
		{"apache-nifi.lua", "GET /nifi-api/processors HTTP/1.1\r\nHost: x\r\n\r\n", "nifi-api-probe"},
		{"apache-druid.lua", "GET /druid/indexer/v1/sampler HTTP/1.1\r\nHost: x\r\n\r\n", "druid-indexer-probe"},
		{"apache-ambari.lua", "GET /api/v1/clusters HTTP/1.1\r\nHost: x\r\n\r\n", "ambari-api-probe"},
		{"argocd.lua", "GET /api/v1/applications HTTP/1.1\r\nHost: x\r\n\r\n", "argocd-api-probe"},
		{"kong.lua", "GET /services HTTP/1.1\r\nHost: x\r\n\r\n", "kong-admin-api-probe"},
		{"owncloud.lua", "GET /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php HTTP/1.1\r\nHost: x\r\n\r\n", "owncloud-cve-2023-49103-probe"},
		{"seafile.lua", "GET /api2/auth-token/ HTTP/1.1\r\nHost: x\r\n\r\n", "seafile-auth-probe"},
		{"synology-dsm.lua", "GET /webapi/auth.cgi?api=SYNO.API.Auth HTTP/1.1\r\nHost: x\r\n\r\n", "synology-webapi-probe"},
		{"pfsense.lua", "GET /pfblockerng/www/index.php?host=x HTTP/1.1\r\nHost: x\r\n\r\n", "pfsense-cve-2022-31814-probe"},
		{"opnsense.lua", "GET /api/core/firmware/status HTTP/1.1\r\nHost: x\r\n\r\n", "opnsense-api-probe"},
		{"unifi.lua", "POST /api/login HTTP/1.1\r\nHost: x\r\n\r\n", "unifi-api-probe"},
		{"juniper-junos.lua", "POST /webauth_operation.php HTTP/1.1\r\nHost: x\r\n\r\n", "junos-cve-2023-36845-probe"},
		{"nagios-xi.lua", "GET /nagiosxi/login.php HTTP/1.1\r\nHost: x\r\n\r\n", "nagiosxi-probe"},
		{"librenms.lua", "GET /api/v0/devices HTTP/1.1\r\nHost: x\r\n\r\n", "librenms-api-probe"},
		{"prtg.lua", "GET /public/checklogin.htm HTTP/1.1\r\nHost: x\r\n\r\n", "prtg-login-probe"},
		{"graylog.lua", "POST /api/system/sessions HTTP/1.1\r\nHost: x\r\n\r\n", "graylog-api-probe"},
		{"bitbucket.lua", "GET /rest/api/1.0/repos/x/y/archive HTTP/1.1\r\nHost: x\r\n\r\n", "bitbucket-cve-2022-36804-probe"},
		{"artifactory.lua", "GET /artifactory/api/repositories HTTP/1.1\r\nHost: x\r\n\r\n", "artifactory-api-probe"},
		{"nomad.lua", "GET /v1/jobs HTTP/1.1\r\nHost: x\r\n\r\n", "nomad-api-probe"},
		{"openshift.lua", "GET /oauth/authorize?response_type=token HTTP/1.1\r\nHost: x\r\n\r\n", "openshift-oauth-probe"},
		{"mlflow.lua", "GET /api/2.0/mlflow/experiments/list HTTP/1.1\r\nHost: x\r\n\r\n", "mlflow-api-probe"},
		{"ray-dashboard.lua", "POST /api/jobs/ HTTP/1.1\r\nHost: x\r\n\r\n", "ray-jobs-api-probe"},
		{"strapi.lua", "POST /admin/login HTTP/1.1\r\nHost: x\r\n\r\n", "strapi-admin-probe"},
		{"joomla-admin.lua", "GET /api/index.php/v1/config/application?public=true HTTP/1.1\r\nHost: x\r\n\r\n", "joomla-cve-2023-23752-probe"},
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
