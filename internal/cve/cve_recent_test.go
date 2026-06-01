package cve

import "testing"

// TestMatchPayloadRecentWebExploits locks in detection of the 2023-2025
// additions: each carries a distinctive request signature.
func TestMatchPayloadRecentWebExploits(t *testing.T) {
	cases := []struct {
		name, handler, req, want string
	}{
		{"Confluence SSTI", "http",
			"POST /template/aui/text-inline.vm HTTP/1.1\r\n\r\nlabel=x", "CVE-2023-22527"},
		{"Check Point traversal", "http",
			"POST /clients/MyCRL HTTP/1.1\r\n\r\naCSHELL/../../../../etc/shadow", "CVE-2024-24919"},
		{"PAN-OS auth bypass", "http",
			"POST /php/utils/createRemoteAppwebSession.php HTTP/1.1\r\n\r\n", "CVE-2024-0012"},
		{"HFS template RCE", "http",
			"GET /?search=%7B.exec%7Cwhoami.%7D HTTP/1.0\r\n\r\n{.exec|whoami.}", "CVE-2024-23692"},
		{"GeoServer OGC RCE", "http",
			"GET /geoserver/wfs?valueReference=exec(java.lang.Runtime.getRuntime()) HTTP/1.1\r\n\r\n", "CVE-2024-36401"},
		{"Bricks Builder RCE", "http",
			"POST /wp-json/bricks/v1/render_element HTTP/1.1\r\n\r\n", "CVE-2024-25600"},
		{"TP-Link Archer cmdi", "http",
			"POST /cgi-bin/luci HTTP/1.1\r\n\r\noperation=write&country=$(id)", "CVE-2023-1389"},
		{"Serv-U traversal", "http",
			"GET /?InternalDir=../../../../&InternalFile=x HTTP/1.1\r\n\r\n", "CVE-2024-28995"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.handler, c.req)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %s; got %+v", c.name, c.want, hits)
		}
	}
}

// TestRecentAdvisoryRecords confirms the binary/handshake exploits are present
// as advisory-only (no payload signature) but still ATT&CK-tagged.
func TestRecentAdvisoryRecords(t *testing.T) {
	for _, id := range []string{"CVE-2023-48795", "CVE-2024-21762", "CVE-2025-22457"} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (no signatures)", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}

// TestMatchPayloadSecondWave locks in the IoT/DVR/camera + enterprise wave.
func TestMatchPayloadSecondWave(t *testing.T) {
	cases := []struct{ name, handler, req, want string }{
		{"D-Link NAS cmdi", "http",
			"GET /cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=;id; HTTP/1.1\r\n\r\n", "CVE-2024-10914"},
		{"TBK DVR cmdi", "http",
			"GET /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sss&cmd=cd+/tmp HTTP/1.1\r\n\r\n", "CVE-2024-3721"},
		{"AVTECH camera", "http",
			"GET /cgi-bin/supervisor/Factory.cgi?action=makeo&brightness=`id` HTTP/1.1\r\n\r\n", "CVE-2024-7029"},
		{"HugeGraph gremlin", "http",
			"POST /apis/gremlin HTTP/1.1\r\n\r\n{\"gremlin\":\"Thread.currentThread()...java.lang.Runtime\"}", "CVE-2024-27348"},
		{"CrushFTP VFS", "http",
			"GET /WebInterface/function/?command=zip&c2f=x HTTP/1.1\r\n\r\n<getFeatureList>", "CVE-2024-4040"},
		{"Telerik Report Server", "http",
			"POST /Startup/Register HTTP/1.1\r\n\r\nUsername=admin", "CVE-2024-4358"},
		{"Confluence addlanguage", "http",
			"POST /admin/plugins/newcode/addlanguage.action HTTP/1.1\r\n\r\n", "CVE-2024-21683"},
		{"FortiClient EMS SQLi", "http",
			"POST / HTTP/1.1\r\n\r\nFCTUID=x';EXEC xp_cmdshell", "CVE-2023-48788"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.handler, c.req)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %s; got %+v", c.name, c.want, hits)
		}
	}
}

// TestSecondWaveAdvisories: the handshake/binary exploits are advisory-only.
func TestSecondWaveAdvisories(t *testing.T) {
	for _, id := range []string{"CVE-2025-32433", "CVE-2024-45519"} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}

// TestMatchPayloadThirdWave locks in the cloud/AI/CMS/2025 wave.
func TestMatchPayloadThirdWave(t *testing.T) {
	cases := []struct{ name, handler, req, want string }{
		{"Ivanti CSA cmdi", "http",
			"POST /gsb/datetime.php HTTP/1.1\r\n\r\nTIMEZONE=;id;", "CVE-2024-8190"},
		{"Aviatrix RCE", "http",
			"POST /v1/api HTTP/1.1\r\n\r\naction=list_flightpath_destination_instances&cloud_type=1", "CVE-2024-50603"},
		{"ShadowRay", "http",
			"POST /api/job_submission/jobs HTTP/1.1\r\n\r\n{\"entrypoint\":\"id\"}", "CVE-2023-48022"},
		{"ChatGPT SSRF", "http",
			"GET /pictureproxy.php?url=http://169.254.169.254/ HTTP/1.1\r\n\r\n", "CVE-2024-27564"},
		{"Next.js bypass", "http",
			"GET /admin HTTP/1.1\r\nx-middleware-subrequest: middleware\r\n\r\n", "CVE-2025-29927"},
		{"Craft CMS RCE", "http",
			"POST /index.php HTTP/1.1\r\n\r\naction=conditions/render&configObject[class]=x", "CVE-2025-32432"},
		{"WP file upload", "http",
			"GET /wp-content/plugins/wp-file-upload/lib/wfu_file_downloader.php?dl=../../wp-config.php HTTP/1.1\r\n\r\n", "CVE-2024-9047"},
		{"WP RSS 2FA bypass", "http",
			"POST /?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding HTTP/1.1\r\n\r\nuser_id=1", "CVE-2024-10924"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.handler, c.req)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %s; got %+v", c.name, c.want, hits)
		}
	}
}

func TestThirdWaveAdvisories(t *testing.T) {
	for _, id := range []string{"CVE-2025-24472", "CVE-2023-44487", "CVE-2024-3596"} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}
