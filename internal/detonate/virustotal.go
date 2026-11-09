package detonate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// virusTotalLookup queries VirusTotal v3 for a file by hash (no upload) and,
// on a hit, pulls the dynamic-analysis network IOCs from its behaviour summary.
// Returns (nil, nil) when VT has never seen the hash (404) — a signal to try the
// sandbox. Network/auth errors return a non-nil error.
func (d *Detonator) virusTotalLookup(ctx context.Context, sha256 string) (*Verdict, error) {
	body, status, err := d.vtGet(ctx, "/files/"+sha256)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return &Verdict{SHA256: sha256, Source: "virustotal", Found: false}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("virustotal files: status %d", status)
	}

	var fr struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
				TypeTags          []string       `json:"type_tags"`
				PopularThreat     struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
					PopularThreatName    []struct {
						Value string `json:"value"`
					} `json:"popular_threat_name"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &fr); err != nil {
		return nil, fmt.Errorf("virustotal files: %w", err)
	}
	a := fr.Data.Attributes
	v := &Verdict{SHA256: sha256, Source: "virustotal", Found: true}
	for k, n := range a.LastAnalysisStats {
		v.Total += n
		if k == "malicious" || k == "suspicious" {
			v.Positives += n
		}
	}
	v.Label = a.PopularThreat.SuggestedThreatLabel
	if len(a.PopularThreat.PopularThreatName) > 0 {
		v.Family = a.PopularThreat.PopularThreatName[0].Value
	}
	v.TypeTags = a.TypeTags

	// Best-effort network IOCs from the sandbox behaviour summary. Free/public
	// keys often 403 here; that's fine — the verdict still stands.
	d.vtBehaviourIOCs(ctx, sha256, v)
	return v, nil
}

// vtBehaviourIOCs augments v with contacted domains/IPs/URLs from the VT
// behaviour summary. Failures are swallowed (best-effort).
func (d *Detonator) vtBehaviourIOCs(ctx context.Context, sha256 string, v *Verdict) {
	body, status, err := d.vtGet(ctx, "/files/"+sha256+"/behaviour_summary")
	if err != nil || status != http.StatusOK {
		return
	}
	var br struct {
		Data struct {
			DNSLookups []struct {
				Hostname string `json:"hostname"`
			} `json:"dns_lookups"`
			IPTraffic []struct {
				DestinationIP string `json:"destination_ip"`
			} `json:"ip_traffic"`
			HTTPConversations []struct {
				URL string `json:"url"`
			} `json:"http_conversations"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &br) != nil {
		return
	}
	for _, x := range br.Data.DNSLookups {
		if h := strings.TrimSpace(x.Hostname); h != "" {
			v.Domains = append(v.Domains, h)
		}
	}
	for _, x := range br.Data.IPTraffic {
		if ip := strings.TrimSpace(x.DestinationIP); ip != "" {
			v.IPs = append(v.IPs, ip)
		}
	}
	for _, x := range br.Data.HTTPConversations {
		if u := strings.TrimSpace(x.URL); u != "" {
			v.URLs = append(v.URLs, u)
		}
	}
	v.Domains = uniq(v.Domains)
	v.IPs = uniq(v.IPs)
	v.URLs = uniq(v.URLs)
}

// vtGet performs a rate-limited, egress-governed GET against the VT API and
// returns the body + status. A 404 is returned as (body, 404, nil), not an error.
func (d *Detonator) vtGet(ctx context.Context, path string) ([]byte, int, error) {
	if err := d.wait(ctx); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.VTBaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("x-apikey", d.vtKey)
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return body, resp.StatusCode, nil
}

func uniq(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
