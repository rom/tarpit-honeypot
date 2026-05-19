package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/sensor"
)

func cmdTestAlert(args []string) error {
	fs := flag.NewFlagSet("test-alert", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	sevStr := fs.String("severity", "high", "severity (low|medium|high|critical)")
	note := fs.String("note", "synthetic event from test-alert", "free-form note in meta.note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sev, err := event.ParseSeverity(*sevStr)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	s, err := sensor.New(cfg)
	if err != nil {
		return err
	}

	ev := &event.Event{
		ID:       event.NewID(),
		Time:     time.Now().UTC(),
		Sensor:   s.Name(),
		RuleID:   "synthetic:test-alert",
		Severity: sev,
		Source:   event.Endpoint{IP: "203.0.113.42", Port: 65000},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Meta:     map[string]any{"note": *note},
	}

	// Drive a single event through the router synchronously.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bus := make(chan *event.Event, 1)
	bus <- ev
	close(bus)
	s.Router().Run(ctx, bus)

	fmt.Println("test-alert sent:", ev.ID)
	return nil
}
