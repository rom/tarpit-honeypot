package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/artifactscan"
)

// cmdAnalyze runs the CGO-free static-analysis engine over a local file
// offline — the same engine the sensor applies to captured artifacts when
// sensor.payloads.analyze is set. Useful for triaging a sample harvested into
// <data_dir>/payloads/ without standing up the sensor, and for testing a
// custom YARA rule directory against a known sample.
//
// Detection only: the file is parsed, hashed, entropy-scored, string/IOC-
// scraped, and rule-matched. Nothing is ever executed.
func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	rules := fs.String("rules", "", "path to a .yar file or directory of YARA-subset rules (in addition to built-ins)")
	asJSON := fs.Bool("json", false, "emit the full report as JSON")
	maxBytes := fs.Int("max-bytes", 32<<20, "read at most this many bytes from the file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: analyze [--rules PATH] [--json] <file>")
	}
	path := fs.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > *maxBytes {
		data = data[:*maxBytes]
	}

	eng := artifactscan.NewEngine()
	if *rules != "" {
		added, errs := eng.LoadDir(*rules)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "rule load: %v\n", e)
		}
		fmt.Fprintf(os.Stderr, "loaded %d rule(s) from %s (engine total %d)\n", added, *rules, eng.RuleCount())
	}
	rep := artifactscan.AnalyzeWith(data, eng)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printReport(path, rep)
	return nil
}

func printReport(path string, r artifactscan.Report) {
	fmt.Printf("file:     %s\n", path)
	fmt.Printf("sha256:   %s\n", r.SHA256)
	fmt.Printf("size:     %d bytes\n", r.Size)
	fmt.Printf("format:   %s — %s\n", r.Format, r.FormatDetail)
	if r.Arch != "" {
		fmt.Printf("arch:     %s\n", r.Arch)
	}
	fmt.Printf("entropy:  %.2f bits/byte", r.Entropy)
	if r.Packed {
		if r.Packer != "" {
			fmt.Printf("  (packed: %s)", r.Packer)
		} else {
			fmt.Print("  (packed)")
		}
	}
	fmt.Println()
	if len(r.Sections) > 0 {
		fmt.Println("sections:")
		for _, s := range r.Sections {
			fmt.Printf("  %-24s %8d  entropy %.2f\n", s.Name, s.Size, s.Entropy)
		}
	}
	if len(r.Imports) > 0 {
		fmt.Printf("imports:  %d (%s%s)\n", len(r.Imports), joinUpTo(r.Imports, 8), more(r.Imports, 8))
	}
	if len(r.Suspicious) > 0 {
		fmt.Println("suspicious traits:")
		for _, s := range r.Suspicious {
			fmt.Printf("  - %s\n", s)
		}
	}
	if !r.IOCs.Empty() {
		fmt.Println("iocs:")
		printIOCLine("urls", r.IOCs.URLs)
		printIOCLine("ipv4", r.IOCs.IPv4)
		printIOCLine("domains", r.IOCs.Domains)
		printIOCLine("emails", r.IOCs.Emails)
		printIOCLine("onion", r.IOCs.Onion)
		printIOCLine("bitcoin", r.IOCs.Bitcoin)
	}
	if len(r.YaraMatches) > 0 {
		fmt.Println("yara matches:")
		for _, m := range r.YaraMatches {
			tags := ""
			if len(m.Tags) > 0 {
				tags = " [" + joinUpTo(m.Tags, 8) + "]"
			}
			fmt.Printf("  - %s%s\n", m.Rule, tags)
		}
	} else {
		fmt.Println("yara matches: none")
	}
}

func printIOCLine(label string, vals []string) {
	if len(vals) == 0 {
		return
	}
	fmt.Printf("  %-8s %s%s\n", label, joinUpTo(vals, 8), more(vals, 8))
}

func joinUpTo(s []string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func more(s []string, n int) string {
	if len(s) > n {
		return fmt.Sprintf(", +%d more", len(s)-n)
	}
	return ""
}
