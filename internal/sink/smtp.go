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
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type smtpSink struct {
	id       string
	host     string
	port     int
	starttls bool
	from     string
	to       []string
	user     string
	pass     string
}

func newSMTP(ch config.Channel) (*smtpSink, error) {
	s := &smtpSink{
		id:       ch.ID,
		host:     ch.Host,
		port:     ch.Port,
		starttls: ch.StartTLS,
		from:     ch.From,
		to:       ch.To,
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
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
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
	pretty, _ := json.MarshalIndent(ev, "", "  ")
	subject := fmt.Sprintf("[tarpit-honeypot %s] %s from %s", ev.Severity, ev.RuleID, ev.Source.IP)
	headers := []string{
		"From: " + s.from,
		"To: " + strings.Join(s.to, ", "),
		"Subject: " + subject,
		"X-Tarpit-Event-ID: " + ev.ID,
		"X-Tarpit-Severity: " + ev.Severity.String(),
		"Content-Type: text/plain; charset=utf-8",
		"MIME-Version: 1.0",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + string(pretty) + "\r\n"
}
