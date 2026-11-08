// Command cvedoc regenerates docs/CVE.md from the live internal/cve catalog.
//
// It is the single source of truth for the CVE reference doc: run it whenever
// the catalog changes so the overview rankings, the full list, and the
// protocol- and product-focused cross-references stay in sync with the code.
//
//	go run ./tools/cvedoc            # writes docs/CVE.md
//	go run ./tools/cvedoc -out -     # prints to stdout
//
// Vendor/product are taken from each record's CPE when present (authoritative)
// and otherwise parsed from the record name; protocol is the catalog Service;
// year is parsed from the CVE id.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/cve"
)

func main() {
	out := flag.String("out", "docs/CVE.md", `output file ("-" for stdout)`)
	flag.Parse()

	doc := Render(cve.All())

	if *out == "-" {
		fmt.Print(doc)
		return
	}
	if err := os.WriteFile(*out, []byte(doc), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "cvedoc:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "cvedoc: wrote %s (%d CVEs)\n", *out, len(cve.All()))
}

// row is the flattened, display-ready view of one catalog record.
type row struct {
	ID, Name, Protocol, Vendor, Product, Technique, Tactic string
	Year                                                   string
	CVSS                                                   float64
	Detectable                                             bool
}

func toRows(recs []cve.Record) []row {
	out := make([]row, 0, len(recs))
	for _, r := range recs {
		v, p := vendorProduct(r)
		out = append(out, row{
			ID: r.ID, Name: r.Name, Protocol: r.Service,
			Vendor: v, Product: p, Technique: r.Technique, Tactic: r.Tactic,
			Year: yearOf(r.ID), CVSS: r.CVSS, Detectable: len(r.Signatures) > 0,
		})
	}
	return out
}

func yearOf(id string) string {
	// CVE-YYYY-NNNN
	parts := strings.Split(id, "-")
	if len(parts) >= 2 && len(parts[1]) == 4 {
		return parts[1]
	}
	return "unknown"
}

// vendorProduct returns a display vendor and "vendor product" label, preferring
// the CPE (cpe:2.3:part:vendor:product:…) and falling back to parsing the name.
func vendorProduct(r cve.Record) (vendor, product string) {
	if v, p, ok := fromCPE(r.CPE); ok {
		return v, joinVendorProduct(v, p)
	}
	v, p := fromName(r.Name)
	if p == "" {
		return v, v
	}
	return v, p
}

// joinVendorProduct builds a "Vendor Product" label without doubling the vendor
// when the product token already is, or begins with, the vendor (ntp/ntp →
// "NTP"; linux/linux_kernel → "Linux Kernel").
func joinVendorProduct(vendor, product string) string {
	if product == "" || strings.EqualFold(product, vendor) {
		return vendor
	}
	if strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)+" ") {
		return product
	}
	return vendor + " " + product
}

func fromCPE(cpe string) (vendor, product string, ok bool) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", false
	}
	f := strings.Split(cpe, ":")
	if len(f) < 5 {
		return "", "", false
	}
	v, p := f[3], f[4]
	if v == "" || v == "*" {
		return "", "", false
	}
	vendor = prettyToken(v)
	if p != "" && p != "*" {
		product = strings.TrimSuffix(prettyToken(p), " Firmware")
	}
	return vendor, product, true
}

// nameTypeWords mark where a product name ends and the weakness class begins in
// a CISA-style "<Vendor> <Product> <Weakness> Vulnerability" title.
var nameTypeWords = map[string]bool{
	"remote": true, "os": true, "sql": true, "directory": true, "path": true,
	"authentication": true, "deserialization": true, "cross-site": true,
	"server-side": true, "missing": true, "improper": true, "unrestricted": true,
	"information": true, "code": true, "local": true, "buffer": true, "use": true,
	"arbitrary": true, "unauthenticated": true, "insecure": true, "hard-coded": true,
	"hardcoded": true, "out-of-bounds": true, "heap": true, "stack": true, "xml": true,
	"eval": true, "incorrect": true, "security": true, "privilege": true, "memory": true,
	"integer": true, "format": true, "reflected": true, "command": true, "injection": true,
	"traversal": true, "disclosure": true, "bypass": true, "overflow": true, "execution": true,
	"inclusion": true, "forgery": true, "escalation": true, "deserialisation": true,
	"vulnerability": true, "vulnerabilities": true, "weakness": true, "flaw": true,
}

// fromName parses "<Vendor> <Product words…> <weakness class>" into a vendor and
// a "vendor product" label. Best-effort: used only for records without a CPE.
func fromName(name string) (vendor, product string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unknown", "unknown"
	}
	words := strings.Fields(name)
	vendor = words[0]
	// Product words: from the second word up to (but not including) the first
	// weakness-class word, capped so a long title can't swallow the whole name.
	var prod []string
	for i := 1; i < len(words) && len(prod) < 4; i++ {
		if nameTypeWords[strings.ToLower(strings.Trim(words[i], "(),"))] {
			break
		}
		prod = append(prod, words[i])
	}
	if len(prod) == 0 {
		return vendor, vendor
	}
	return vendor, vendor + " " + strings.Join(prod, " ")
}

// acronyms keeps known all-caps / brand spellings when prettifying a CPE token.
var acronyms = map[string]string{
	"abb": "ABB", "hpe": "HPE", "ibm": "IBM", "isc": "ISC", "sap": "SAP",
	"qnap": "QNAP", "netgear": "NETGEAR", "zyxel": "ZyXEL", "hitachienergy": "Hitachi Energy",
	"powerdns": "PowerDNS", "gitlab": "GitLab", "vmware": "VMware", "microscada_x_sys600": "MicroSCADA X SYS600",
	"thekelleys": "Thekelleys", "dropbear_ssh_project": "Dropbear", "rpcbind_project": "rpcbind",
	"ntp": "NTP", "dnsmasq": "dnsmasq", "bind": "BIND", "sun": "Sun", "d-link": "D-Link",
	"tp-link": "TP-Link", "draytek": "DrayTek", "solarwinds": "SolarWinds", "freepbx": "FreePBX",
	"aspect-enterprise": "ASPECT", "rtu500": "RTU500", "fox61x": "FOX61x", "rmc-100": "Totalflow RMC-100",
	"openbsd": "OpenBSD", "openssh": "OpenSSH", "fortios": "FortiOS", "fortinet": "Fortinet",
	"http": "HTTP", "http_server": "HTTP Server", "php": "PHP", "iis": "IIS",
	"macos": "macOS", "esxi": "ESXi", "netscaler": "NetScaler", "jboss": "JBoss", "websphere": "WebSphere",
}

func prettyToken(tok string) string {
	low := strings.ToLower(tok)
	if a, ok := acronyms[low]; ok {
		return a
	}
	parts := strings.FieldsFunc(tok, func(r rune) bool { return r == '_' })
	for i, p := range parts {
		if a, ok := acronyms[strings.ToLower(p)]; ok {
			parts[i] = a
		} else {
			parts[i] = strings.Title(strings.ToLower(p)) //nolint:staticcheck // ASCII product tokens
		}
	}
	return strings.Join(parts, " ")
}

// --- aggregation -------------------------------------------------------------

type countEntry struct {
	Key   string
	Count int
}

func topN(counts map[string]int, n int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for k, c := range counts {
		entries = append(entries, countEntry{k, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func countBy(rows []row, f func(row) string) map[string]int {
	m := map[string]int{}
	for _, r := range rows {
		if k := f(r); k != "" && k != "unknown" {
			m[k]++
		}
	}
	return m
}

// --- rendering ---------------------------------------------------------------

func Render(recs []cve.Record) string {
	rows := toRows(recs)
	var b strings.Builder

	b.WriteString("# CVE catalog\n\n")
	b.WriteString("This is the auto-generated reference for every CVE the tarpit-honeypot\n")
	b.WriteString("catalog knows about — the vulnerabilities it emulates (fake-vulnerable banners\n")
	b.WriteString("and patch-level advisories) and detects (exploit-attempt signatures matched by\n")
	b.WriteString("`internal/cve.MatchPayload`). A **detectable** CVE carries an exploit signature\n")
	b.WriteString("so a live attempt is flagged; the rest are advisory-only (binary/off-path/\n")
	b.WriteString("credential issues) surfaced for banner and patch-level emulation.\n\n")
	b.WriteString("> Generated by `tools/cvedoc` from `internal/cve`. Do not edit by hand — run\n")
	b.WriteString("> `go run ./tools/cvedoc` to regenerate after changing the catalog.\n\n")

	detectable := 0
	for _, r := range rows {
		if r.Detectable {
			detectable++
		}
	}
	fmt.Fprintf(&b, "**%d CVEs** in the catalog — %d detectable (exploit-signatured), %d advisory-only.\n\n",
		len(rows), detectable, len(rows)-detectable)

	b.WriteString("## Contents\n\n")
	b.WriteString("- [Overview — top 10s](#overview--top-10s)\n")
	b.WriteString("- [By protocol / service](#by-protocol--service)\n")
	b.WriteString("- [By product / tool](#by-product--tool)\n")
	b.WriteString("- [All CVEs](#all-cves)\n\n")

	// ---- Overview: four top-10 tables ----
	b.WriteString("## Overview — top 10s\n\n")

	writeTop(&b, "Top 10 products by CVE count", "Product", topN(countBy(rows, func(r row) string { return r.Product }), 10))
	writeTop(&b, "Top 10 vendors by CVE count", "Vendor", topN(countBy(rows, func(r row) string { return r.Vendor }), 10))
	writeTop(&b, "Top 10 protocols / services by CVE count", "Protocol / service", topN(countBy(rows, func(r row) string { return r.Protocol }), 10))
	writeTop(&b, "Top 10 years by CVE count", "Year", topN(countBy(rows, func(r row) string { return r.Year }), 10))

	// ---- By protocol ----
	b.WriteString("## By protocol / service\n\n")
	b.WriteString("Every protocol/service the honeypot answers on, with its catalogued CVEs. A\n")
	b.WriteString("protocol can map to many CVEs.\n\n")
	writeGrouped(&b, rows, func(r row) string { return r.Protocol }, "protocol")

	// ---- By product ----
	b.WriteString("## By product / tool\n\n")
	b.WriteString("Every product/tool, with its catalogued CVEs (vendor+product from CPE where\n")
	b.WriteString("available, else parsed from the CVE name). A product can map to many CVEs.\n\n")
	writeGrouped(&b, rows, func(r row) string { return r.Product }, "product")

	// ---- Full list ----
	b.WriteString("## All CVEs\n\n")
	b.WriteString("| CVE | Name | Protocol | CVSS | Detect | ATT&CK |\n")
	b.WriteString("|-----|------|----------|------|--------|--------|\n")
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s |\n",
			nvdLink(r.ID), esc(r.Name), r.Protocol, cvss(r.CVSS), detectMark(r.Detectable), attack(r))
	}
	b.WriteString("\n")

	return b.String()
}

func writeTop(b *strings.Builder, title, col string, entries []countEntry) {
	fmt.Fprintf(b, "### %s\n\n", title)
	fmt.Fprintf(b, "| Rank | %s | CVEs |\n|-----|------|------|\n", col)
	for i, e := range entries {
		fmt.Fprintf(b, "| %d | %s | %d |\n", i+1, esc(e.Key), e.Count)
	}
	b.WriteString("\n")
}

// writeGrouped emits one subsection per group key (sorted by CVE count desc),
// each listing that group's CVEs. Singletons are collapsed into a trailing note
// to keep the protocol/product views navigable.
func writeGrouped(b *strings.Builder, rows []row, key func(row) string, noun string) {
	groups := map[string][]row{}
	for _, r := range rows {
		k := key(r)
		if k == "" || k == "unknown" {
			k = "(unclassified)"
		}
		groups[k] = append(groups[k], r)
	}
	names := make([]string, 0, len(groups))
	for k := range groups {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(groups[names[i]]) != len(groups[names[j]]) {
			return len(groups[names[i]]) > len(groups[names[j]])
		}
		return names[i] < names[j]
	})
	var singles []string
	for _, name := range names {
		g := groups[name]
		if len(g) == 1 {
			singles = append(singles, fmt.Sprintf("%s (%s)", esc(name), nvdLink(g[0].ID)))
			continue
		}
		sort.Slice(g, func(i, j int) bool { return g[i].ID < g[j].ID })
		fmt.Fprintf(b, "### %s — %d CVEs\n\n", esc(name), len(g))
		b.WriteString("| CVE | Name | CVSS | Detect |\n|-----|------|------|--------|\n")
		for _, r := range g {
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", nvdLink(r.ID), esc(r.Name), cvss(r.CVSS), detectMark(r.Detectable))
		}
		b.WriteString("\n")
	}
	if len(singles) > 0 {
		sort.Strings(singles)
		fmt.Fprintf(b, "### Single-CVE %ss\n\n", noun)
		b.WriteString(strings.Join(singles, " · "))
		b.WriteString("\n\n")
	}
}

func nvdLink(id string) string {
	return fmt.Sprintf("[%s](https://nvd.nist.gov/vuln/detail/%s)", id, id)
}

func detectMark(d bool) string {
	if d {
		return "✓ live"
	}
	return "advisory"
}

func cvss(v float64) string {
	if v <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f", v)
}

func attack(r row) string {
	if r.Technique == "" {
		return "—"
	}
	if r.Tactic == "" {
		return "`" + r.Technique + "`"
	}
	return "`" + r.Technique + "` / " + r.Tactic
}

// esc escapes the Markdown table cell separator so a name with a pipe can't
// break the column layout.
func esc(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
