package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

// SIEM / chat delivery sinks: Slack + Microsoft Teams (incoming webhooks),
// Elasticsearch/OpenSearch (document index), and Splunk HEC. All POST over the
// egress-governed HTTP client, so the destination host must be allowlisted when
// egress.enforce is on (see Dests). Secrets (webhook URL, API key, HEC token)
// come from env vars, never inline YAML.

// channelURL resolves ch.URL, falling back to the URLEnv environment variable.
func channelURL(ch config.Channel) string {
	if ch.URL != "" {
		return ch.URL
	}
	if ch.URLEnv != "" {
		return os.Getenv(ch.URLEnv)
	}
	return ""
}

func postJSON(ctx context.Context, client *http.Client, url string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tarpit-honeypot")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// eventSummary is a one-line human summary used by the chat sinks.
func eventSummary(ev *event.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(ev.Severity.String()), ev.RuleID)
	if ev.Source.IP != "" {
		fmt.Fprintf(&b, " from %s", ev.Source.IP)
	}
	if ev.Handler != "" {
		fmt.Fprintf(&b, " → %s", ev.Handler)
	}
	if ev.Dest.Port != 0 {
		fmt.Fprintf(&b, ":%d", ev.Dest.Port)
	}
	if ev.Sensor != "" {
		fmt.Fprintf(&b, " (%s)", ev.Sensor)
	}
	return b.String()
}

// --- Slack / Teams incoming webhooks -------------------------------------

type chatSink struct {
	id     string
	kind   string // "slack" | "teams"
	url    string
	client *http.Client
}

func newChat(ch config.Channel, kind string) (*chatSink, error) {
	u := channelURL(ch)
	if u == "" {
		return nil, fmt.Errorf("%s %s: url (or url_env) required", kind, ch.ID)
	}
	return &chatSink{id: ch.ID, kind: kind, url: u, client: egress.HTTPClient(ch.Timeout)}, nil
}

func (c *chatSink) ID() string { return c.id }

func (c *chatSink) Send(ctx context.Context, ev *event.Event) error {
	text := eventSummary(ev)
	var payload any
	if c.kind == "teams" {
		// Minimal MessageCard (Teams incoming webhook).
		payload = map[string]any{
			"@type": "MessageCard", "@context": "http://schema.org/extensions",
			"summary": "tarpit-honeypot event", "title": "tarpit-honeypot: " + ev.RuleID,
			"text": text,
		}
	} else {
		payload = map[string]any{"text": "🪤 " + text}
	}
	body, _ := json.Marshal(payload)
	return postJSON(ctx, c.client, c.url, body, nil)
}

func (c *chatSink) Close() error { return nil }

// --- Elasticsearch / OpenSearch ------------------------------------------

type esSink struct {
	id     string
	url    string // base URL, e.g. https://es:9200
	index  string
	apiKey string
	client *http.Client
	fmtr   format.Formatter
}

func newElasticsearch(ch config.Channel, f format.Formatter) (*esSink, error) {
	base := strings.TrimRight(channelURL(ch), "/")
	if base == "" {
		return nil, fmt.Errorf("elasticsearch %s: url (or url_env) required", ch.ID)
	}
	idx := ch.Index
	if idx == "" {
		idx = "tarpit-events"
	}
	s := &esSink{id: ch.ID, url: base, index: idx, client: egress.HTTPClient(ch.Timeout), fmtr: f}
	if ch.AuthTokenEnv != "" {
		s.apiKey = os.Getenv(ch.AuthTokenEnv)
	}
	return s, nil
}

func (s *esSink) ID() string { return s.id }

func (s *esSink) Send(ctx context.Context, ev *event.Event) error {
	body, err := s.fmtr.Format(ev)
	if err != nil {
		return err
	}
	hdr := map[string]string{}
	if s.apiKey != "" {
		hdr["Authorization"] = "ApiKey " + s.apiKey
	}
	// Index one document (id = event id → idempotent re-delivery).
	return postJSON(ctx, s.client, s.url+"/"+s.index+"/_doc/"+ev.ID, body, hdr)
}

func (s *esSink) Close() error { return nil }

// --- Splunk HEC ----------------------------------------------------------

type splunkSink struct {
	id     string
	url    string // HEC event endpoint, e.g. https://splunk:8088/services/collector/event
	token  string
	client *http.Client
	fmtr   format.Formatter
}

func newSplunkHEC(ch config.Channel, f format.Formatter) (*splunkSink, error) {
	u := channelURL(ch)
	if u == "" {
		return nil, fmt.Errorf("splunk_hec %s: url (or url_env) required", ch.ID)
	}
	if !strings.Contains(u, "/services/collector") {
		u = strings.TrimRight(u, "/") + "/services/collector/event"
	}
	s := &splunkSink{id: ch.ID, url: u, client: egress.HTTPClient(ch.Timeout), fmtr: f}
	if ch.AuthTokenEnv != "" {
		s.token = os.Getenv(ch.AuthTokenEnv)
	}
	if s.token == "" {
		return nil, fmt.Errorf("splunk_hec %s: auth_token_env required (HEC token)", ch.ID)
	}
	return s, nil
}

func (s *splunkSink) ID() string { return s.id }

func (s *splunkSink) Send(ctx context.Context, ev *event.Event) error {
	payload, err := s.fmtr.Format(ev)
	if err != nil {
		return err
	}
	// Wrap the formatted event in the HEC envelope. For JSON the event is the
	// object; for cef/leef/ocsf it rides as a string, which Splunk accepts.
	var inner any
	if s.fmtr.Name() == "json" || s.fmtr.Name() == "ocsf" {
		inner = json.RawMessage(payload)
	} else {
		inner = string(payload)
	}
	env := map[string]any{
		"time":       float64(ev.Time.UnixNano()) / 1e9,
		"host":       ev.Sensor,
		"source":     "tarpit-honeypot",
		"sourcetype": "tarpit:event",
		"event":      inner,
	}
	body, _ := json.Marshal(env)
	return postJSON(ctx, s.client, s.url, body, map[string]string{"Authorization": "Splunk " + s.token})
}

func (s *splunkSink) Close() error { return nil }
