package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/kevsync"
)

// cmdKEVGap runs a CISA KEV coverage gap-scan: it pulls the KEV catalog (live
// from the feed, or from a local --file) and prints the KEV-listed CVEs the
// sensor's compile-time catalog does not yet model — the actively-exploited
// vulnerabilities worth adding — newest-first. With --covered it instead lists
// the KEV CVEs the sensor already covers.
func cmdKEVGap(args []string) error {
	fs := flag.NewFlagSet("kev-gap", flag.ContinueOnError)
	url := fs.String("url", kevsync.DefaultURL, "CISA KEV JSON feed URL")
	file := fs.String("file", "", "read the KEV JSON from a local file instead of the network")
	header := fs.String("header", "", "optional request header \"Name: value\" (e.g. an API key)")
	covered := fs.Bool("covered", false, "list the KEV CVEs already in the catalog instead of the gaps")
	asJSON := fs.Bool("json", false, "emit as JSON instead of a table")
	timeout := fs.Duration("timeout", 30*time.Second, "network fetch timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		entries []kevsync.Entry
		version string
		err     error
	)
	if *file != "" {
		b, rerr := os.ReadFile(*file)
		if rerr != nil {
			return rerr
		}
		entries, err = kevsync.Parse(b)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		// A one-shot operator command: a plain client that honours HTTP(S)_PROXY
		// from the environment (the sensor's background puller uses the
		// egress-governed client instead).
		client := &http.Client{Timeout: *timeout, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
		entries, version, err = kevsync.Fetch(ctx, client, *url, *header)
	}
	if err != nil {
		return fmt.Errorf("kev-gap: could not load the KEV catalog: %w\n"+
			"  the feed host must be reachable from this host — allow %q in the egress/network policy,\n"+
			"  or download it elsewhere and pass --file known_exploited_vulnerabilities.json", err, hostOf(*url))
	}

	// The sensor's modeled CVE ids (compile-time catalog).
	have := make([]string, 0)
	for _, r := range cve.All() {
		have = append(have, r.ID)
	}
	haveSet := map[string]struct{}{}
	for _, id := range have {
		haveSet[strings.ToUpper(id)] = struct{}{}
	}

	var rows []kevsync.Entry
	if *covered {
		for _, e := range entries {
			if _, ok := haveSet[e.CVEID]; ok {
				rows = append(rows, e)
			}
		}
	} else {
		rows = kevsync.GapScan(entries, have)
	}

	if *asJSON {
		return writeJSON(rows)
	}

	label := "GAP (not modeled)"
	if *covered {
		label = "COVERED"
	}
	fmt.Printf("CISA KEV catalog: %d entries", len(entries))
	if version != "" {
		fmt.Printf(" (version %s)", version)
	}
	fmt.Printf("; sensor models %d CVEs; %d %s.\n\n", len(have), len(rows), strings.ToLower(label))
	if len(rows) == 0 {
		return nil
	}
	fmt.Printf("%-18s %-12s %-4s %-22s %s\n", "CVE", "ADDED", "RNSM", "VENDOR/PRODUCT", "NAME")
	for _, e := range rows {
		rnsm := "-"
		if e.KnownRansomware {
			rnsm = "yes"
		}
		vp := strings.TrimSpace(e.VendorProject + "/" + e.Product)
		fmt.Printf("%-18s %-12s %-4s %-22s %s\n", e.CVEID, dash(e.DateAdded), rnsm, clip(vp, 22), dash(e.Name))
	}
	return nil
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
