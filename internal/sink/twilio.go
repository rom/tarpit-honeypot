package sink

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type twilioSink struct {
	id       string
	endpoint string
	authSID  string
	authTok  string
	from     string
	to       []string
	client   *http.Client
}

func newTwilio(ch config.Channel) (Sink, error) {
	sid := os.Getenv(ch.AccountSIDEnv)
	tok := os.Getenv(ch.AuthTokenEnv)
	if sid == "" || tok == "" {
		return nil, fmt.Errorf("twilio %s: account_sid_env (%s) or auth_token_env (%s) is empty",
			ch.ID, ch.AccountSIDEnv, ch.AuthTokenEnv)
	}
	if ch.From == "" || len(ch.To) == 0 {
		return nil, fmt.Errorf("twilio %s: from and to are required", ch.ID)
	}
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", sid)
	return &twilioSink{
		id:       ch.ID,
		endpoint: endpoint,
		authSID:  sid,
		authTok:  tok,
		from:     ch.From,
		to:       ch.To,
		client:   egress.HTTPClient(10 * time.Second),
	}, nil
}

func (t *twilioSink) ID() string { return t.id }

func (t *twilioSink) Send(ctx context.Context, ev *event.Event) error {
	body := fmt.Sprintf("[%s] %s from %s on %s:%d", ev.Severity, ev.RuleID, ev.Source.IP, ev.Dest.IP, ev.Dest.Port)
	if len(body) > 1500 {
		body = body[:1500]
	}
	// Twilio sends one SMS per recipient. We loop rather than batching so one
	// bad number doesn't sink the others.
	var firstErr error
	for _, dst := range t.to {
		form := url.Values{}
		form.Set("From", t.from)
		form.Set("To", dst)
		form.Set("Body", body)
		req, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		req.SetBasicAuth(t.authSID, t.authTok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := t.client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// Drain and close so the connection can be reused.
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			if firstErr == nil {
				firstErr = fmt.Errorf("twilio: status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
			}
		}
	}
	return firstErr
}

func (t *twilioSink) Close() error { return nil }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
