package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type webhookSink struct {
	id     string
	url    string
	secret []byte
	client *http.Client
}

func newWebhook(ch config.Channel) (*webhookSink, error) {
	w := &webhookSink{
		id:     ch.ID,
		url:    ch.URL,
		client: &http.Client{Timeout: ch.Timeout},
	}
	if ch.HMACSecretEnv != "" {
		secret := os.Getenv(ch.HMACSecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("webhook %s: env %s is empty", ch.ID, ch.HMACSecretEnv)
		}
		w.secret = []byte(secret)
	}
	return w, nil
}

func (w *webhookSink) ID() string { return w.id }

func (w *webhookSink) Send(ctx context.Context, ev *event.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tarpit-honeypot/0.1")
	req.Header.Set("X-Tarpit-Event-ID", ev.ID)
	req.Header.Set("X-Tarpit-Time", ev.Time.Format(time.RFC3339Nano))
	if len(w.secret) > 0 {
		mac := hmac.New(sha256.New, w.secret)
		mac.Write(body)
		req.Header.Set("X-Tarpit-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s: status %d", w.id, resp.StatusCode)
	}
	return nil
}

func (w *webhookSink) Close() error { return nil }
