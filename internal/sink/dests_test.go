package sink

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestDests(t *testing.T) {
	cases := []struct {
		name string
		ch   config.Channel
		want []string
	}{
		{"webhook", config.Channel{Type: "webhook", URL: "https://siem.example:8443/ingest"}, []string{"siem.example:8443"}},
		{"webhook-no-port", config.Channel{Type: "webhook", URL: "https://siem.example/ingest"}, []string{"siem.example:443"}},
		{"mqtt", config.Channel{Type: "mqtt", URL: "tls://broker.example:8883"}, []string{"broker.example:8883"}},
		{"syslog-tcp", config.Channel{Type: "syslog", Network: "tcp", Address: "log.example:6514"}, []string{"log.example:6514"}},
		{"syslog-local", config.Channel{Type: "syslog", Network: "local"}, nil},
		{"sns", config.Channel{Type: "sns", Region: "us-east-1"}, []string{"sns.us-east-1.amazonaws.com:443"}},
		{"smtp", config.Channel{Type: "smtp", Host: "mail.example", Port: 587}, []string{"mail.example:587"}},
		{"twilio", config.Channel{Type: "twilio"}, []string{"api.twilio.com:443"}},
		{"stdout", config.Channel{Type: "stdout"}, nil},
		{"jsonlog", config.Channel{Type: "jsonlog"}, nil},
		{"sqlite", config.Channel{Type: "sqlite"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Dests(c.ch)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("Dests(%s) = %v; want %v", c.name, got, c.want)
			}
		})
	}
}
