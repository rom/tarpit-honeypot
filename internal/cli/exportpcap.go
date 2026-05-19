package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdExportPcap copies one event's pcap out of <data_dir>/captures/. The
// file at <event_id>.pcap is written under listener.capture=true. The
// command is read-only — it never modifies the sensor's state.
func cmdExportPcap(args []string) error {
	fs := flag.NewFlagSet("export-pcap", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	eventID := fs.String("event", "", "event id whose pcap to export (required)")
	outPath := fs.String("o", "-", "output file ('-' = stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventID == "" {
		return fmt.Errorf("--event is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	src := filepath.Join(cfg.Sensor.DataDir, "captures", *eventID+".pcap")
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("export-pcap: %w", err)
	}
	defer in.Close()
	var out io.Writer = os.Stdout
	if *outPath != "-" {
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	n, err := io.Copy(out, in)
	if err != nil {
		return err
	}
	if *outPath != "-" {
		fmt.Fprintf(os.Stderr, "export-pcap: wrote %d bytes to %s\n", n, *outPath)
	}
	return nil
}
