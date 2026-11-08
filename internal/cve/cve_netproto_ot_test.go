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
