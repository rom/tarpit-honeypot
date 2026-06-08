package listener

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDeriveEventIntent(t *testing.T) {
	cases := []struct {
		name    string
		handler string
		meta    map[string]any
		anoms   []string
		want    string
	}{
		{name: "handler-set wins", handler: "dns", meta: map[string]any{"intent": "DNS tunneling"}, want: "DNS tunneling"},
		{name: "cve anywhere", handler: "redis", meta: map[string]any{"x": 1}, anoms: []string{"cve:CVE-2022-0543"}, want: "exploit attempt (CVE-2022-0543)"},
		{name: "ssh shell", handler: "ssh_interactive", meta: map[string]any{"shell_commands": []string{"id", "uname -a"}}, want: "interactive shell session"},
		{name: "ssh login", handler: "ssh_interactive", meta: map[string]any{"user_attempt": "root"}, want: "remote-access login attempt"},
		{name: "telnet probe", handler: "telnet", meta: map[string]any{"telnet_env": "x"}, want: "remote-access probe"},
		{name: "smtp relay", handler: "smtp_recv", meta: map[string]any{"mail_from": "a@x", "rcpt_to": "b@y"}, want: "mail send / relay attempt"},
		{name: "imap login", handler: "imaps", meta: map[string]any{"auth_user": "admin"}, want: "mail login attempt"},
		{name: "postgres auth", handler: "postgres", meta: map[string]any{"user": "postgres"}, want: "database auth attempt"},
		{name: "redis cmd", handler: "redis", meta: map[string]any{"commands": []string{"CONFIG GET dir"}}, want: "database command / query"},
		{name: "mongo probe", handler: "mongodb", meta: map[string]any{"x": 1}, want: "database probe / banner-grab"},
		{name: "uncategorized", handler: "ftp_files", meta: map[string]any{"x": 1}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &event.Event{Handler: tc.handler, Meta: tc.meta, Anomalies: tc.anoms}
			deriveEventIntent(ev)
			got, _ := ev.Meta["intent"].(string)
			if got != tc.want {
				t.Errorf("intent = %q; want %q", got, tc.want)
			}
		})
	}
}
