package testharness

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// APIClient queries the target sensor's read-only web API so that misimpl /
// scan / fingerprint cases can confirm the honeypot actually recorded the
// activity. Optional — when unconfigured those cases report skip rather than
// guessing.
type APIClient struct {
	base  string
	token string
	hc    *http.Client
}

// NewAPIClient builds a client for a base URL like http://127.0.0.1:8088.
func NewAPIClient(base, token string) *APIClient {
	return &APIClient{base: strings.TrimRight(base, "/"), token: token, hc: &http.Client{Timeout: 8 * time.Second}}
}

type apiEvent struct {
	RuleID    string   `json:"rule_id"`
	Anomalies []string `json:"anomalies"`
	Handler   string   `json:"handler"`
	Source    struct {
		IP string `json:"ip"`
	} `json:"source"`
	Meta map[string]any `json:"meta"`
}

// Events fetches recent events (since e.g. "5m", up to limit).
func (c *APIClient) Events(ctx context.Context, since string, limit int) ([]apiEvent, error) {
	u := fmt.Sprintf("%s/api/events?since=%s&limit=%d", c.base, since, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api %s: status %d", u, resp.StatusCode)
	}
	var evs []apiEvent
	if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
		return nil, err
	}
	return evs, nil
}

// Detected reports whether any recent event matches a predicate: a rule_id
// prefix, an exact anomaly marker, or a tool/scanner classification. Returns
// (matched, checked) — checked=false means the API was unreachable so the
// caller should skip rather than fail.
func (c *APIClient) Detected(ctx context.Context, match func(apiEvent) bool) (matched, checked bool) {
	evs, err := c.Events(ctx, "10m", 5000)
	if err != nil {
		return false, false
	}
	for _, e := range evs {
		if match(e) {
			return true, true
		}
	}
	return false, true
}

// MatchAnomaly matches an event carrying a specific anomaly marker.
func MatchAnomaly(marker string) func(apiEvent) bool {
	return func(e apiEvent) bool {
		for _, a := range e.Anomalies {
			if a == marker {
				return true
			}
		}
		return false
	}
}

// MatchRulePrefix matches an event whose rule_id starts with prefix.
func MatchRulePrefix(prefix string) func(apiEvent) bool {
	return func(e apiEvent) bool { return strings.HasPrefix(e.RuleID, prefix) }
}

// MatchTool matches an event the sensor attributed to a named scanning/attack
// tool (via the meta.tools list or a tool:* / scanner anomaly marker).
func MatchTool(tool string) func(apiEvent) bool {
	tool = strings.ToLower(tool)
	return func(e apiEvent) bool {
		if tl, ok := e.Meta["tools"].([]any); ok {
			for _, t := range tl {
				if s, ok := t.(string); ok && strings.Contains(strings.ToLower(s), tool) {
					return true
				}
			}
		}
		for _, a := range e.Anomalies {
			la := strings.ToLower(a)
			if strings.Contains(la, tool) || la == "vulnerability-scanner" || strings.HasPrefix(la, "tool:") {
				return true
			}
		}
		return false
	}
}
