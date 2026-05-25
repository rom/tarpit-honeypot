package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// discordSink posts events to a Discord channel via an incoming-webhook
// URL. Discord requires its own JSON shape (content + embeds), so this sink
// builds a severity-colored embed rather than using a Formatter. Embeds
// don't trigger @mentions, and attacker-controlled meta is sanitized, so a
// captured payload can't ping a channel or smuggle control bytes.
type discordSink struct {
	id     string
	url    string
	client *http.Client
}

func newDiscord(ch config.Channel) (Sink, error) {
	u := ch.URL
	if ch.URLEnv != "" {
		if v := os.Getenv(ch.URLEnv); v != "" {
			u = v
		}
	}
	if u == "" {
		return nil, fmt.Errorf("discord %s: url (or url_env) required", ch.ID)
	}
	to := ch.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	return &discordSink{id: ch.ID, url: u, client: egress.HTTPClient(to)}, nil
}

func (d *discordSink) ID() string { return d.id }

type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title     string         `json:"title"`
	Color     int            `json:"color"`
	Fields    []discordField `json:"fields,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func (d *discordSink) Send(ctx context.Context, ev *event.Event) error {
	payload := discordPayload{
		Username: "tarpit-honeypot",
		Embeds: []discordEmbed{{
			Title:     discordTrunc(orDash(ev.RuleID), 240),
			Color:     discordColor(ev.Severity),
			Fields:    discordFields(ev),
			Timestamp: ev.Time.UTC().Format(time.RFC3339),
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tarpit-honeypot")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord %s: status %d", d.id, resp.StatusCode)
	}
	return nil
}

func (d *discordSink) Close() error { return nil }

func discordColor(sev event.Severity) int {
	switch sev {
	case event.SeverityCritical:
		return 0xE01E5A // red
	case event.SeverityHigh:
		return 0xE67E22 // orange
	case event.SeverityMedium:
		return 0xF1C40F // yellow
	default:
		return 0x3498DB // blue
	}
}

func discordFields(ev *event.Event) []discordField {
	fields := []discordField{
		{Name: "Severity", Value: ev.Severity.String(), Inline: true},
	}
	if ev.Source.IP != "" {
		fields = append(fields, discordField{Name: "Source", Value: safe.SanitizeForLog(ev.Source.IP), Inline: true})
	}
	if len(ev.Meta) > 0 {
		keys := make([]string, 0, len(ev.Meta))
		for k := range ev.Meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		n := 0
		for _, k := range keys {
			if n >= 6 {
				break
			}
			fmt.Fprintf(&b, "%s: %v\n", k, ev.Meta[k])
			n++
		}
		if b.Len() > 0 {
			fields = append(fields, discordField{
				Name:  "Details",
				Value: discordTrunc(safe.SanitizeForLog(b.String()), 1000),
			})
		}
	}
	return fields
}

func discordTrunc(s string, max int) string {
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "event"
	}
	return s
}
