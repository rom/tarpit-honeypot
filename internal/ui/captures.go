package ui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Captures ("loot") tab: a single place to retrieve everything the sensor
// harvested from attackers — captured malware/payload artifacts, per-connection
// pcaps, recorded interactive-shell sessions, and captured credentials. Files
// are listed from the data dir and served (read-only, attachment) by the
// /loot/ route; credentials are read from the event store. Disabled when no
// data_dir is wired.

const capturesWindow = 30 * 24 * time.Hour
const capturesScanMax = 20000

type lootFile struct {
	Name  string    // basename (download key)
	Size  int64     // bytes
	MTime time.Time // last-modified (≈ capture end time)
	Kind  string    // pcap | session | payload
	// SrcIP / DstPort are parsed from the pcap filename
	// (<eventID>_<srcIP>_<dstPort>.pcap) so the captures page can show who the
	// capture is of and which port they hit. Empty for the legacy <id>.pcap form.
	SrcIP   string
	DstPort string
}

type capturesView struct {
	Enabled   bool
	Pcaps     []lootFile
	Sessions  []lootFile
	Artifacts []lootFile
	Creds     []credRow
	Since     time.Time
	Scanned   int
	// Credential-capture summary counters (clickable filters), computed over
	// the whole window regardless of the active filter.
	KindCounts    []counter
	ServiceCounts []counter
	TotalCreds    int    // total deduped creds before the active filter
	FilterKind    string // active ?kind= filter ("" = none)
	FilterService string // active ?service= filter ("" = none)
}

type credRow struct {
	Time      time.Time
	Source    string
	Service   string
	Kind      string // password | token | api-key | snmp-community | cookie | kerberos-ticket | honeytoken
	KindLabel string // Kind, defaulting to "password" when empty (display + filter key)
	User      string
	Pass      string
}

// lootDir maps the UI "kind" to its subdirectory under data_dir.
var lootDir = map[string]string{
	"pcap":    "captures",
	"session": "sessions",
	"payload": "payloads",
}

// parsePcapName extracts the source IP and destination port from a pcap
// filename of the form "<eventID>_<srcIP>_<dstPort>.pcap" (the scheme written
// by internal/capture). An IPv6 source has its ':' rendered as '-' in the
// filename; we restore it here. Returns ("","") for the legacy "<eventID>.pcap"
// form (no underscores) so old captures still list cleanly.
func parsePcapName(name string) (srcIP, dstPort string) {
	base := strings.TrimSuffix(name, ".pcap")
	parts := strings.Split(base, "_")
	if len(parts) != 3 {
		return "", ""
	}
	srcIP, dstPort = parts[1], parts[2]
	if strings.Count(srcIP, ".") != 3 { // not IPv4 -> it's a dash-encoded IPv6
		srcIP = strings.ReplaceAll(srcIP, "-", ":")
	}
	return srcIP, dstPort
}

// listLoot lists the files under <dataDir>/<sub> as lootFiles, newest first,
// capped. Missing/empty dirs yield an empty slice (not an error).
func listLoot(dataDir, kind string, max int) []lootFile {
	sub := lootDir[kind]
	if sub == "" || dataDir == "" {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, sub))
	if err != nil {
		return nil
	}
	out := make([]lootFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		lf := lootFile{Name: e.Name(), Size: fi.Size(), MTime: fi.ModTime(), Kind: kind}
		if kind == "pcap" {
			lf.SrcIP, lf.DstPort = parsePcapName(e.Name())
		}
		out = append(out, lf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MTime.After(out[j].MTime) })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func buildCapturesView(dataDir string, since time.Time, evs []*event.Event, filterKind, filterService string) capturesView {
	v := capturesView{Enabled: dataDir != "", Since: since, Scanned: len(evs), FilterKind: filterKind, FilterService: filterService}
	if dataDir != "" {
		v.Pcaps = listLoot(dataDir, "pcap", 500)
		v.Sessions = listLoot(dataDir, "session", 500)
		v.Artifacts = listLoot(dataDir, "payload", 500)
	}
	// Captured credentials from the event store (newest first, deduped). Counts
	// per type/service are tallied over the whole deduped set so the counters
	// stay stable while you click through filters.
	seen := map[string]struct{}{}
	kindCounts := map[string]int{}
	serviceCounts := map[string]int{}
	var all []credRow
	for _, ev := range evs {
		for _, c := range extractCreds(ev) {
			if c.User == "" && c.Pass == "" {
				continue
			}
			key := ev.Source.IP + "\x00" + c.Kind + "\x00" + c.User + "\x00" + c.Pass + "\x00" + c.Service
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			kindLabel := c.Kind
			if kindLabel == "" {
				kindLabel = "password"
			}
			kindCounts[kindLabel]++
			if c.Service != "" {
				serviceCounts[c.Service]++
			}
			all = append(all, credRow{
				Time: ev.Time, Source: ev.Source.IP, Service: c.Service,
				Kind: c.Kind, KindLabel: kindLabel, User: c.User, Pass: c.Pass,
			})
		}
	}
	v.TotalCreds = len(all)
	v.KindCounts = capturesCounters(kindCounts, "kind", filterKind)
	v.ServiceCounts = capturesCounters(serviceCounts, "service", filterService)
	// Apply the active type/service filter to the displayed rows.
	for _, row := range all {
		if filterKind != "" && row.KindLabel != filterKind {
			continue
		}
		if filterService != "" && row.Service != filterService {
			continue
		}
		v.Creds = append(v.Creds, row)
	}
	return v
}

// capturesCounters turns a label→count map into clickable counter chips for the
// captures page, sorted by count (then label). param is the query key the chip
// links to ("kind"/"service"); active highlights the currently-selected chip.
func capturesCounters(m map[string]int, param, active string) []counter {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, n := range m {
		items = append(items, kv{k, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	out := make([]counter, 0, len(items))
	for _, it := range items {
		cl := ""
		if it.k == active {
			cl = "c-total" // tint the active filter
		}
		out = append(out, counter{
			Label: it.k, Value: it.v, Class: cl,
			Href: "/captures?" + param + "=" + url.QueryEscape(it.k),
		})
	}
	return out
}

func (s *Server) handleCaptures(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-capturesWindow)
	var evs []*event.Event
	if e, err := s.query(ctx, store.Filter{Since: since, Limit: capturesScanMax}); err == nil {
		evs = e
	}
	kind := r.URL.Query().Get("kind")
	service := r.URL.Query().Get("service")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "captures", buildCapturesView(s.dataDir, since, evs, kind, service)); err != nil {
		slog.Warn("ui: render captures", "err", err)
	}
}

// handleLoot serves a single captured file by kind + name, read-only and as an
// attachment. Defense in depth: kind is from a fixed allowlist, the name is
// basename-only (safeJoin) and opened without following a final-component
// symlink. Mirrors handlePcap / handleSession.
func (s *Server) handleLoot(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	kind := r.URL.Query().Get("kind")
	sub := lootDir[kind]
	if sub == "" {
		http.Error(w, "bad kind", http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	p, ok := safeJoin(filepath.Join(s.dataDir, sub), name)
	if !ok {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	f, err := openNoFollow(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	// Always octet-stream + attachment: these are hostile artifacts; never let
	// a browser sniff/execute a captured payload inline.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(p)))
	_, _ = io.Copy(w, f)
}
