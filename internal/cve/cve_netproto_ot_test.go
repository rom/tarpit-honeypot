package cve

import (
	"strings"
	"testing"
)

// TestNetProtoAndOTBatchesWellFormed: the hand-authored protocol + OT batches
// must have a service, an ATT&CK technique/tactic, a sane CVSS, and a name +
// description. (Signatures are optional — most are advisory-only binary/off-path
// issues; the catalog-wide integrity tests separately enforce lowercase sigs and
// unique sorted IDs.)
func TestNetProtoAndOTBatchesWellFormed(t *testing.T) {
	batches := map[string][]Record{"netproto": cveNetProtoBatch, "ot-abb-hitachi": cveOTABBHitachi}
	for name, recs := range batches {
		if len(recs) == 0 {
			t.Errorf("%s batch is empty", name)
		}
		for _, r := range recs {
			if !strings.HasPrefix(r.ID, "CVE-") {
				t.Errorf("%s: %q is not a CVE id", name, r.ID)
			}
			if r.Service == "" || r.Technique == "" || r.Tactic == "" {
				t.Errorf("%s/%s: missing service/technique/tactic", name, r.ID)
			}
			if r.CVSS < 0 || r.CVSS > 10 {
				t.Errorf("%s/%s: CVSS %v out of range", name, r.ID, r.CVSS)
			}
			if r.Name == "" || r.Description == "" {
				t.Errorf("%s/%s: missing name/description", name, r.ID)
			}
		}
	}
}

// TestProtocolServicesRepresented: the batch must actually broaden coverage of
// the services the task targeted (ntp, dns, telnet, ssh) and the amplification
// vectors, so ForService surfaces them for banner/patch-level advertising.
func TestProtocolServicesRepresented(t *testing.T) {
	for _, svc := range []string{"ntp", "dns", "telnet", "ssh", "memcached", "rpcbind"} {
		if len(ForService(svc)) == 0 {
			t.Errorf("no catalog records for service %q", svc)
		}
	}
}

// TestABBAspectDetects: the ABB Cylon Aspect web-delivered command-injection
// endpoints must fire through MatchPayload on the http handler (these are the
// only OT records with a path signature; the rest are advisory-only).
func TestABBAspectDetects(t *testing.T) {
	cases := []struct{ id, payload string }{
		{"CVE-2023-0636", "POST /networkDiagAjax.php HTTP/1.1\r\n\r\nhost=;id;"},
		{"CVE-2024-48839", "POST /servicesUpdate.php HTTP/1.1\r\n\r\nx=1"},
		{"CVE-2024-48840", "GET /deployStart.php?x=1 HTTP/1.1"},
	}
	for _, c := range cases {
		if _, ok := Lookup(c.id); !ok {
			t.Errorf("%s not in catalog", c.id)
			continue
		}
		if hits := MatchPayload("http", c.payload); !containsID(hits, c.id) {
			t.Errorf("%s: MatchPayload did not flag it; got %v", c.id, ids(hits))
		}
	}
}

// TestSNMPDNSNTPBatchWellFormed: the SNMP/DNS/NTP deepening batch must be
// well-formed and must actually broaden those three services' coverage.
func TestSNMPDNSNTPBatchWellFormed(t *testing.T) {
	if len(cveSNMPDNSNTP) == 0 {
		t.Fatal("cveSNMPDNSNTP is empty")
	}
	for _, r := range cveSNMPDNSNTP {
		if !strings.HasPrefix(r.ID, "CVE-") {
			t.Errorf("%q is not a CVE id", r.ID)
		}
		switch r.Service {
		case "snmp", "dns", "ntp":
		default:
			t.Errorf("%s: unexpected service %q (want snmp/dns/ntp)", r.ID, r.Service)
		}
		if r.Technique == "" || r.Tactic == "" || r.Name == "" || r.Description == "" {
			t.Errorf("%s: missing technique/tactic/name/description", r.ID)
		}
		if r.CVSS < 0 || r.CVSS > 10 {
			t.Errorf("%s: CVSS %v out of range", r.ID, r.CVSS)
		}
	}
	// Coverage grew for each targeted service (there were already some records).
	for svc, min := range map[string]int{"snmp": 15, "dns": 30, "ntp": 35} {
		if n := len(ForService(svc)); n < min {
			t.Errorf("service %q has %d records; expected the batch to push it past %d", svc, n, min)
		}
	}
}

// TestNucleiExtraDetects: the curated recent-CVE Nuclei batch must be well-formed
// and a representative spread must fire through MatchPayload on its exploit path.
func TestNucleiExtraDetects(t *testing.T) {
	if len(cveNucleiExtra2026) < 15 {
		t.Fatalf("expected the curated batch to add 15+ CVEs, got %d", len(cveNucleiExtra2026))
	}
	for _, r := range cveNucleiExtra2026 {
		if r.Service != "http" || len(r.Signatures) == 0 || r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s: malformed nuclei-extra record (%+v)", r.ID, r)
		}
	}
	cases := []struct{ id, payload string }{
		{"CVE-2025-30220", "GET /geoserver/wfs?service=wfs&request=getcapabilities HTTP/1.1"},
		{"CVE-2025-41243", "GET /actuator/gateway/routes/ HTTP/1.1"},
		{"CVE-2026-41042", "POST /api/metalakes HTTP/1.1"},
		{"CVE-2026-2699", "GET /configservice/admin.aspx HTTP/1.1"},
		{"CVE-2025-32966", "POST /de2api/datasource/validate HTTP/1.1"},
		{"CVE-2026-86207", "GET /dms;/services/serverui HTTP/1.1"},
	}
	for _, c := range cases {
		if _, ok := Lookup(c.id); !ok {
			t.Errorf("%s not in catalog", c.id)
			continue
		}
		if hits := MatchPayload("http", c.payload); !containsID(hits, c.id) {
			t.Errorf("%s: MatchPayload did not flag it; got %v", c.id, ids(hits))
		}
	}
}

// TestInferredCWEPromotion: the catalog promotes an inferred weakness class onto
// records that lack an explicit CWE, so coverage is near-total and the inference
// is correctly flagged.
func TestInferredCWEPromotion(t *testing.T) {
	if id, ok := inferCWE("Acme SQL Injection Vulnerability", ""); !ok || id != "CWE-89" {
		t.Errorf("SQLi inference = %q ok=%v", id, ok)
	}
	if id, ok := inferCWE("Foo Directory Traversal", ""); !ok || id != "CWE-22" {
		t.Errorf("traversal inference = %q ok=%v", id, ok)
	}
	if _, ok := inferCWE("completely unclassifiable text", ""); ok {
		t.Error("unclassifiable should not infer a CWE")
	}
	var withCWE, inferred int
	for _, r := range All() {
		if len(r.CWE) > 0 {
			withCWE++
		}
		if CWEInferred(r.ID) {
			inferred++
			if len(r.CWE) == 0 {
				t.Errorf("%s is marked inferred but has no CWE on the record", r.ID)
			}
		}
	}
	// Promotion should take coverage well past the explicitly-authored set.
	if withCWE < len(All())*95/100 {
		t.Errorf("CWE coverage only %d/%d; expected >=95%% after promotion", withCWE, len(All()))
	}
	if inferred == 0 {
		t.Error("expected some records to carry an inferred CWE")
	}
}
