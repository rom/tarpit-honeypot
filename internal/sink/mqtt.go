package sink

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

// mqttSink publishes events to an MQTT broker. The sensor acts as an
// MQTT client; the broker is reached via tcp://broker:1883 or
// tls://broker:8883 (or ws://, wss://). Each event becomes one
// message published to the configured topic.
type mqttSink struct {
	id        string
	client    mqtt.Client
	topic     string
	qos       byte
	retain    bool
	formatter format.Formatter
}

func newMQTT(ch config.Channel, f format.Formatter) (Sink, error) {
	if ch.URL == "" {
		return nil, fmt.Errorf("mqtt %s: url required (e.g. tcp://broker:1883)", ch.ID)
	}
	if _, err := url.Parse(ch.URL); err != nil {
		return nil, fmt.Errorf("mqtt %s: bad url %q: %w", ch.ID, ch.URL, err)
	}
	topic := ch.Topic
	if topic == "" {
		topic = "tarpit/events"
	}
	opts := mqtt.NewClientOptions().
		AddBroker(ch.URL).
		SetClientID(ch.ID + "-" + nowSuffix()).
		SetAutoReconnect(true).
		SetConnectTimeout(5 * time.Second).
		SetMaxReconnectInterval(60 * time.Second).
		SetKeepAlive(60 * time.Second).
		SetOrderMatters(false)
	if ch.UsernameEnv != "" {
		opts.SetUsername(os.Getenv(ch.UsernameEnv))
	}
	if ch.PasswordEnv != "" {
		opts.SetPassword(os.Getenv(ch.PasswordEnv))
	}
	// TLS brokers (tls:// ssl:// wss://): apply custom CA / insecure / SNI
	// when any TLS option is set; otherwise paho uses the system roots.
	if isTLSBroker(ch.URL) && (ch.TLSInsecure || ch.CACertFile != "" || ch.TLSServerName != "") {
		tlsCfg, err := buildTLSConfig(ch)
		if err != nil {
			return nil, fmt.Errorf("mqtt %s: %w", ch.ID, err)
		}
		opts.SetTLSConfig(tlsCfg)
	}
	c := mqtt.NewClient(opts)
	if token := c.Connect(); token.WaitTimeout(5*time.Second) && token.Error() != nil {
		return nil, fmt.Errorf("mqtt %s: connect: %w", ch.ID, token.Error())
	}
	return &mqttSink{
		id:        ch.ID,
		client:    c,
		topic:     topic,
		qos:       byte(ch.QoS),
		retain:    ch.Retain,
		formatter: f,
	}, nil
}

func (m *mqttSink) ID() string { return m.id }

func (m *mqttSink) Send(ctx context.Context, ev *event.Event) error {
	body, err := m.formatter.Format(ev)
	if err != nil {
		return err
	}
	if !m.client.IsConnected() {
		return fmt.Errorf("mqtt %s: broker not connected", m.id)
	}
	token := m.client.Publish(m.topic, m.qos, m.retain, body)
	deadline := 5 * time.Second
	if d, ok := ctx.Deadline(); ok {
		deadline = time.Until(d)
	}
	if !token.WaitTimeout(deadline) {
		return fmt.Errorf("mqtt %s: publish timed out", m.id)
	}
	return token.Error()
}

func (m *mqttSink) Close() error {
	if m.client != nil {
		m.client.Disconnect(250)
	}
	return nil
}

func nowSuffix() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func isTLSBroker(u string) bool {
	return strings.HasPrefix(u, "tls://") || strings.HasPrefix(u, "ssl://") || strings.HasPrefix(u, "wss://")
}
