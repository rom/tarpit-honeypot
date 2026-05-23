package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

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
//
// Selector flags pick which slice of the inventory to show (first one
// set wins, in the order documented in the usage). Two report flags
// override the table: --stats prints an aggregate summary and
// --conflicts lists IPs bound to multiple MACs (an ARP-spoof signal).
func cmdListDevices(args []string) error {
	fs := flag.NewFlagSet("list-devices", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	asJSON := fs.Bool("json", false, "emit the inventory as JSON")
	stats := fs.Bool("stats", false, "print an aggregate summary instead of the table")
	conflicts := fs.Bool("conflicts", false, "list IPs bound to multiple MACs (ARP-spoof candidates)")
	rogues := fs.Bool("rogues", false, "show only non-allow-listed (rogue) devices")
	class := fs.String("class", "", "show only devices of this inferred class (scanner/ics-endpoint/network-device/web-host/host)")
	vendor := fs.String("vendor", "", "show only devices whose OUI vendor contains this substring")
	search := fs.String("search", "", "show only devices matching this substring (ip/mac/hostname/vendor/attrs)")
	stale := fs.Duration("stale", 0, "show only devices NOT seen within this duration (e.g. 24h)")
	active := fs.Duration("active", 0, "show only devices seen within this duration (e.g. 1h)")
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

	// Report modes override the device table.
	if *stats {
		return printDeviceStats(reg.Stats(), *asJSON)
	}
	if *conflicts {
		return printDeviceConflicts(reg.Conflicts(), *asJSON)
	}

	// Selector flags choose which slice to list (first set wins).
	now := time.Now().UTC()
	var list []devices.Device
	switch {
	case *rogues:
		list = reg.Rogues()
	case *class != "":
		list = reg.ByClass(*class)
	case *vendor != "":
		list = reg.ByVendor(*vendor)
	case *search != "":
		list = reg.Search(*search)
	case *stale > 0:
		list = reg.Stale(*stale, now)
	case *active > 0:
		list = reg.Active(*active, now)
	default:
		list = reg.List()
	}

	if len(list) == 0 {
		fmt.Println("(no matching devices)")
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

	fmt.Printf("%-16s %-18s %-22s %-20s %-9s %-14s %s\n",
		"IP", "MAC", "VENDOR", "HOSTNAME", "SOURCE", "CLASS", "LAST SEEN")
	for _, d := range list {
		fmt.Printf("%-16s %-18s %-22s %-20s %-9s %-14s %s\n",
			dash(d.IP), dash(d.MAC), dash(d.Vendor), dash(d.Hostname),
			string(d.Source), dash(d.Attrs["class"]), d.LastSeen.Format("2006-01-02 15:04"))
	}
	fmt.Printf("\n%d device(s).\n", len(list))
	return nil
}

// printDeviceStats renders the aggregate inventory summary.
func printDeviceStats(st devices.Stats, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	fmt.Printf("devices: %d total · %d allow-listed · %d rogue\n", st.Total, st.Allowed, st.Rogue)
	fmt.Printf("by source: %s\n", joinCounts(st.BySource))
	fmt.Printf("by class:  %s\n", joinCounts(st.ByClass))
	return nil
}

// printDeviceConflicts renders IPs that map to more than one MAC.
func printDeviceConflicts(cs []devices.Conflict, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cs)
	}
	if len(cs) == 0 {
		fmt.Println("(no IP/MAC conflicts)")
		return nil
	}
	fmt.Printf("%-16s %s\n", "IP", "MACS (possible ARP spoof / impersonation)")
	for _, c := range cs {
		fmt.Printf("%-16s %s\n", c.IP, joinStrs(c.MACs))
	}
	fmt.Printf("\n%d conflict(s).\n", len(cs))
	return nil
}

// joinCounts renders a count map as "k=v" pairs sorted by key.
func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	if out == "" {
		return "-"
	}
	return out
}

// joinStrs joins a slice with ", ".
func joinStrs(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
