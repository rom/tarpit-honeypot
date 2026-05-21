package sink

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

// streamSyslog sends events to a syslog collector over a stream transport
// (tcp or tls) using RFC 5424 message format with RFC 6587 octet-counting
// framing — the framing RFC 5425 (syslog over TLS) mandates. The stdlib
// log/syslog can't do TLS and uses BSD framing, so network=tcp|tls route
// here instead. It reconnects once on a write failure (collectors drop
// idle connections). Cross-platform (network I/O only), so it builds on
// Windows too.
type streamSyslog struct {
	id        string
	network   string // "tcp" | "tls"
	address   string
	tag       string
	hostname  string
	pid       int
	tlsCfg    *tls.Config
	formatter format.Formatter

	mu   sync.Mutex
	conn net.Conn
}

func newStreamSyslog(ch config.Channel, f format.Formatter) (Sink, error) {
	s := &streamSyslog{
		id: ch.ID, network: ch.Network, address: ch.Address,
		tag: ch.Tag, formatter: f, pid: os.Getpid(),
	}
	if s.tag == "" {
		s.tag = "tarpit-honeypot"
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		s.hostname = h
	} else {
		s.hostname = "-"
	}
	if ch.Network == "tls" {
		cfg, err := buildTLSConfig(ch)
		if err != nil {
			return nil, fmt.Errorf("syslog %s: %w", ch.ID, err)
		}
		if cfg.ServerName == "" {
			cfg.ServerName = hostOnly(ch.Address)
		}
		s.tlsCfg = cfg
	}
	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("syslog %s: dial %s %s: %w", ch.ID, ch.Network, ch.Address, err)
	}
	return s, nil
}

func (s *streamSyslog) ID() string { return s.id }

func (s *streamSyslog) connect() error {
	d := &net.Dialer{Timeout: 5 * time.Second}
	var (
		c   net.Conn
		err error
	)
	if s.network == "tls" {
		c, err = tls.DialWithDialer(d, "tcp", s.address, s.tlsCfg)
	} else {
		c, err = d.Dial("tcp", s.address)
	}
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

func (s *streamSyslog) Send(ctx context.Context, ev *event.Event) error {
	b, err := s.formatter.Format(ev)
	if err != nil {
		return err
	}
	frame := s.frame(ev, b)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = s.conn.SetWriteDeadline(deadline)
	if _, err := s.conn.Write(frame); err != nil {
		// Reconnect-and-retry once.
		_ = s.conn.Close()
		s.conn = nil
		if err2 := s.connect(); err2 != nil {
			return err
		}
		_ = s.conn.SetWriteDeadline(deadline)
		if _, err3 := s.conn.Write(frame); err3 != nil {
			return err3
		}
	}
	return nil
}

// frame builds the octet-counted RFC 5424 frame: "<LEN> <SYSLOG-MSG>".
func (s *streamSyslog) frame(ev *event.Event, msg []byte) []byte {
	pri := 3*8 + sevToSyslog(ev.Severity) // facility daemon(3)
	ts := ev.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	header := fmt.Sprintf("<%d>1 %s %s %s %d - - ",
		pri, ts.UTC().Format(time.RFC3339), s.hostname, s.tag, s.pid)
	full := append([]byte(header), msg...)
	return append([]byte(fmt.Sprintf("%d ", len(full))), full...)
}

// sevToSyslog maps an event severity to a syslog severity level.
func sevToSyslog(sev event.Severity) int {
	switch sev {
	case event.SeverityCritical:
		return 2 // crit
	case event.SeverityHigh:
		return 3 // err
	case event.SeverityMedium:
		return 4 // warning
	default:
		return 6 // info
	}
}

func (s *streamSyslog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
