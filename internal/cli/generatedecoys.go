package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rom/tarpit-honeypot/internal/decoygen"
)

// cmdGenerateDecoys scans the operator's own network and writes a
// tarpit-honeypot listener config that mirrors the services it finds, so the
// honeypot blends into the environment it is deployed in. It is a benign TCP
// connect scanner (no exploit traffic, no stealth scanning, no writes to the
// target) bounded by an explicit target list + a host cap.
//
//	generate-decoys [flags] <target>...
//	  target: host | host:port | CIDR (e.g. 10.0.0.0/24)
func cmdGenerateDecoys(args []string) error {
	fs := flag.NewFlagSet("generate-decoys", flag.ContinueOnError)
	portsCSV := fs.String("ports", "", "comma-separated TCP ports to probe (default: curated common set)")
	timeout := fs.Duration("timeout", 2*time.Second, "per-connection dial/read timeout")
	concurrency := fs.Int("concurrency", 64, "max concurrent connections")
	maxHosts := fs.Int("max-hosts", 256, "cap on expanded host count (anti-mass-scan guard)")
	bind := fs.String("bind", "0.0.0.0", "bind address for the generated listeners")
	archetype := fs.String("archetype", "", "sensor.archetype to stamp on the generated config")
	sensorName := fs.String("name", "", "sensor.name for the generated config")
	readTimeout := fs.String("read-timeout", "30s", "read_timeout for the generated listeners")
	noBanners := fs.Bool("no-banners", false, "skip banner / TLS-cert grabbing (faster, less faithful)")
	out := fs.String("o", "", "output file (default stdout)")
	yes := fs.Bool("yes", false, "confirm you are authorized to scan the targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := fs.Args()
	if len(targets) == 0 {
		return fmt.Errorf("usage: generate-decoys [flags] <target>...  (host | host:port | CIDR)\n" +
			"scans your own network and emits a matching honeypot config; see -h for flags")
	}

	if !*yes {
		return fmt.Errorf("refusing to scan: pass --yes to confirm you are authorized to scan %s.\n"+
			"generate-decoys actively connects to the targets — only run it against networks you own or are authorized to assess",
			strings.Join(targets, ", "))
	}

	ports, err := parsePorts(*portsCSV)
	if err != nil {
		return err
	}

	opts := decoygen.Options{
		Targets:     targets,
		Ports:       ports,
		Timeout:     *timeout,
		Concurrency: *concurrency,
		MaxHosts:    *maxHosts,
		GrabBanners: !*noBanners,
	}

	// Ctrl-C cancels the scan cleanly and still emits whatever was found.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "scanning %s (%d ports each, timeout %s) — connect scan only…\n",
		strings.Join(targets, ", "), len(opts.PortsOrDefault()), *timeout)
	res, err := decoygen.Scan(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "found %d open service(s) across %d host(s)\n", len(res.Services), res.Hosts)

	yamlCfg, err := decoygen.Generate(res, decoygen.GenOptions{
		Bind: *bind, Archetype: *archetype, SensorName: *sensorName, ReadTimeout: *readTimeout,
	})
	if err != nil {
		return err
	}

	if *out == "" {
		fmt.Print(yamlCfg)
		return nil
	}
	if err := os.WriteFile(*out, []byte(yamlCfg), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes) — review it, then validate with: tarpit-honeypot validate-config -c %s\n",
		*out, len(yamlCfg), *out)
	return nil
}

// parsePorts parses a comma-separated port list; empty returns nil (the
// scanner falls back to its curated default set).
func parsePorts(csv string) ([]int, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var ports []int
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, err := strconv.Atoi(tok)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %q", tok)
		}
		ports = append(ports, p)
	}
	return ports, nil
}
