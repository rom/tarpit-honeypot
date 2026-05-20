package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/devices"
)

// cmdListDevices prints the learned-device inventory persisted at
// <data_dir>/devices.json. It is read-only — it loads the same
// registry the running sensor maintains (with the configured
// allow-list applied) and dumps it as a table or JSON.
//
// Operators use this to review what the sensor has seen on the wire
// and to snapshot a baseline (`--json > baseline.json`).
func cmdListDevices(args []string) error {
	fs := flag.NewFlagSet("list-devices", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	asJSON := fs.Bool("json", false, "emit the inventory as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	reg := devices.New(devices.Config{
		DataDir: cfg.Sensor.DataDir,
		Allow:   cfg.Devices.Allow,
		Learn:   cfg.Devices.Learn,
	})
	list := reg.List()
	if len(list) == 0 {
		fmt.Println("(no devices learned yet)")
		if !cfg.Devices.Enabled {
			fmt.Fprintln(os.Stderr, "note: devices.enabled is false in the config; nothing is being recorded")
		}
		return nil
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}

	fmt.Printf("%-16s %-18s %-22s %-20s %-9s %s\n",
		"IP", "MAC", "VENDOR", "HOSTNAME", "SOURCE", "LAST SEEN")
	for _, d := range list {
		fmt.Printf("%-16s %-18s %-22s %-20s %-9s %s\n",
			dash(d.IP), dash(d.MAC), dash(d.Vendor), dash(d.Hostname),
			string(d.Source), d.LastSeen.Format("2006-01-02 15:04"))
	}
	fmt.Printf("\n%d device(s).\n", len(list))
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
