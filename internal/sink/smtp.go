package sink

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type smtpSink struct {
	id        string
	host      string
	port      int
	starttls  bool
	from      string
	to        []string
	user      string
	pass      string
	formatter format.Formatter
}

func newSMTP(ch config.Channel, f format.Formatter) (*smtpSink, error) {
	s := &smtpSink{
		id:        ch.ID,
		host:      ch.Host,
		port:      ch.Port,
		starttls:  ch.StartTLS,
		from:      ch.From,
		to:        ch.To,
		formatter: f,
	}
	if ch.UsernameEnv != "" {
		s.user = os.Getenv(ch.UsernameEnv)
	}
	if ch.PasswordEnv != "" {
		s.pass = os.Getenv(ch.PasswordEnv)
	}
	return s, nil
}

func (s *smtpSink) ID() string { return s.id }

func (s *smtpSink) Send(ctx context.Context, ev *event.Event) error {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))
	conn, err := egress.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()

	if s.starttls {
		if err := c.StartTLS(&tls.Config{ServerName: s.host}); err != nil {
			return err
		}
	}
	if s.user != "" {
		auth := smtp.PlainAuth("", s.user, s.pass, s.host)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.from); err != nil {
		return err
	}
	for _, r := range s.to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	body := s.formatBody(ev)
	if _, err := w.Write([]byte(body)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *smtpSink) Close() error { return nil }

func (s *smtpSink) formatBody(ev *event.Event) string {
	var body string
	if s.formatter.Name() == "json" {
		// JSON body looks better pretty-printed in an email client.
		pretty, _ := json.MarshalIndent(ev, "", "  ")
		body = string(pretty)
	} else {
		b, _ := s.formatter.Format(ev)
		body = string(b)
	}
	// Every field that flows into a header has to be safe.
	// SanitizeHeader strips CR/LF/NUL so an attacker who somehow lands
	// a CRLF in an event field can't break MIME structure or inject a
	// hidden Bcc: header.
	subject := safe.SanitizeEmailSubject(fmt.Sprintf("[tarpit-honeypot %s] %s from %s",
		ev.Severity, safe.SanitizeHeader(ev.RuleID), safe.SanitizeHeader(ev.Source.IP)))
	headers := []string{
		"From: " + safe.SanitizeHeader(s.from),
		"To: " + safe.SanitizeHeader(strings.Join(s.to, ", ")),
		"Subject: " + subject,
		"X-Tarpit-Event-ID: " + safe.SanitizeHeader(ev.ID),
		"X-Tarpit-Severity: " + safe.SanitizeHeader(ev.Severity.String()),
		"X-Tarpit-Format: " + safe.SanitizeHeader(s.formatter.Name()),
		"Content-Type: " + safe.SanitizeHeader(s.formatter.ContentType()),
		"MIME-Version: 1.0",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
}
