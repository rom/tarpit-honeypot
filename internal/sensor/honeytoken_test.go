package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// A login attempt that reuses a security.txt contact name must be flagged,
// across protocols, from the username meta key each handler uses.
func TestObserveHoneytokenAccount(t *testing.T) {
	enabled := true
	s := &Sensor{name: "t", cfg: &config.Config{
		Listeners: []config.Listener{
			{Handler: "http", WebDeception: config.WebDeception{
				Enabled:          &enabled,
				SecurityContacts: []string{"soc@corp.example", "abuse@corp.example"},
			}},
			{Handler: "ftp"},
		},
	}}

	// FTP login as the local-part "soc" → flagged.
	ftp := &event.Event{Handler: "ftp", Meta: map[string]any{"user": "soc", "pass": "x"}}
	s.observeHoneytokenAccount(ftp)
	if !hasAnomaly(ftp, "honeytoken:account-login") {
		t.Errorf("ftp honeytoken login not flagged: %v", ftp.Anomalies)
	}
	if ftp.Meta["honeytoken_account"] != "soc" {
		t.Errorf("honeytoken_account meta = %v", ftp.Meta["honeytoken_account"])
	}

	// IMAP login as the full address → flagged (auth_user key).
	imap := &event.Event{Handler: "imap", Meta: map[string]any{"auth_user": "abuse@corp.example"}}
	s.observeHoneytokenAccount(imap)
	if !hasAnomaly(imap, "honeytoken:account-login") {
		t.Errorf("imap honeytoken login not flagged: %v", imap.Anomalies)
	}

	// A normal username is not flagged.
	normal := &event.Event{Handler: "ssh", Meta: map[string]any{"username": "root"}}
	s.observeHoneytokenAccount(normal)
	if hasAnomaly(normal, "honeytoken:account-login") {
		t.Error("ordinary username should not be flagged")
	}
}

// With no http/https listener advertising security.txt there are no honeytokens.
func TestHoneytokenAccountsEmptyWithoutWeb(t *testing.T) {
	s := &Sensor{name: "t", cfg: &config.Config{
		Listeners: []config.Listener{{Handler: "ftp"}},
	}}
	if len(s.honeytokenAccounts()) != 0 {
		t.Errorf("no web listener -> no honeytokens, got %v", s.honeytokenAccounts())
	}
	ev := &event.Event{Meta: map[string]any{"user": "security"}}
	s.observeHoneytokenAccount(ev)
	if hasAnomaly(ev, "honeytoken:account-login") {
		t.Error("must not flag when no honeytokens are configured")
	}
}
