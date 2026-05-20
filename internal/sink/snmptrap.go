package sink

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// snmpTrapSink sends an SNMPv2c trap PDU per event. Each event becomes a
// trap with vendor-prefixed OIDs holding the rule id, severity, source IP,
// and the event id. Configurable enterprise OID + community.
type snmpTrapSink struct {
	id        string
	host      string
	port      uint16
	community string
	oid       string
	version   g.SnmpVersion
}

func newSNMPTrap(ch config.Channel) (Sink, error) {
	if ch.Host == "" {
		return nil, fmt.Errorf("snmptrap %s: host required", ch.ID)
	}
	port := uint16(162)
	if ch.Port != 0 {
		port = uint16(ch.Port)
	}
	// Prefer the env-sourced community so the write credential stays out of
	// the config file / show-config output; fall back to inline, then public.
	community := ch.Community
	if ch.CommunityEnv != "" {
		if v := os.Getenv(ch.CommunityEnv); v != "" {
			community = v
		}
	}
	if community == "" {
		community = "public"
	}
	oid := ch.EnterpriseOID
	if oid == "" {
		// IANA private enterprise number for "experimental"; operators
		// should set their own.
		oid = "1.3.6.1.4.1.65535"
	}
	return &snmpTrapSink{
		id:        ch.ID,
		host:      ch.Host,
		port:      port,
		community: community,
		oid:       oid,
		version:   g.Version2c,
	}, nil
}

func (s *snmpTrapSink) ID() string { return s.id }

func (s *snmpTrapSink) Send(ctx context.Context, ev *event.Event) error {
	client := &g.GoSNMP{
		Target:    s.host,
		Port:      s.port,
		Community: s.community,
		Version:   s.version,
		Timeout:   5 * time.Second,
		Retries:   1,
	}
	if d, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(d)
	}
	if err := client.Connect(); err != nil {
		return fmt.Errorf("snmptrap: connect: %w", err)
	}
	defer client.Conn.Close()

	srcCombined := ev.Source.IP
	if ev.Source.Port > 0 {
		srcCombined = net.JoinHostPort(ev.Source.IP, strconv.Itoa(ev.Source.Port))
	}
	pdus := []g.SnmpPDU{
		{Name: s.oid + ".1", Type: g.OctetString, Value: ev.ID},
		{Name: s.oid + ".2", Type: g.OctetString, Value: ev.RuleID},
		{Name: s.oid + ".3", Type: g.OctetString, Value: ev.Severity.String()},
		{Name: s.oid + ".4", Type: g.OctetString, Value: srcCombined},
		{Name: s.oid + ".5", Type: g.OctetString, Value: ev.Sensor},
	}
	trap := g.SnmpTrap{
		Variables:  pdus,
		Enterprise: s.oid,
	}
	if _, err := client.SendTrap(trap); err != nil {
		return fmt.Errorf("snmptrap: send: %w", err)
	}
	return nil
}

func (s *snmpTrapSink) Close() error { return nil }
