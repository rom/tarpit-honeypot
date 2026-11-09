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
	// Malware-detonation verdict (payload artifacts only; Verdict=false when the
	// sample hasn't been looked up / detonated). Joined from malware:detonation
	// events by sha256 — see internal/detonate.
	Verdict      bool
	MalFamily    string // malware family (VT popular_threat_name / sandbox label)
	AVLabel      string // suggested threat label (fallback when family is empty)
	AVHits       int    // AV engines flagging the sample
	AVTotal      int    // AV engines that scored it
	DetSource    string // "virustotal" | "cape"
	IOCCount     int    // contacted domains+IPs+URLs the detonation revealed
	VerdictEvent string // event ID of the malware:detonation event (for click-through)
}

// artifactSHA256 extracts the sha256 from a payload artifact filename of the
// form "<sha256>.<ext>" (or a bare "<sha256>").
func artifactSHA256(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(name)
}

// detonationVerdicts indexes the latest/richest malware:detonation verdict per
// sha256 across the scanned events, for joining onto captured artifacts.
func detonationVerdicts(evs []*event.Event) map[string]lootFile {
	out := map[string]lootFile{}
	for _, ev := range evs {
		if ev.RuleID != "malware:detonation" || ev.Meta == nil {
			continue
		}
		h := strings.ToLower(metaString(ev.Meta, "file_sha256"))
		if len(h) != 64 {
			continue
		}
		vd := lootFile{
			Verdict:      true,
			MalFamily:    metaString(ev.Meta, "malware_family"),
			AVLabel:      metaString(ev.Meta, "av_label"),
			AVHits:       metaInt(ev.Meta, "av_positives"),
			AVTotal:      metaInt(ev.Meta, "av_total"),
			DetSource:    metaString(ev.Meta, "detonation_source"),
			VerdictEvent: ev.ID,
			IOCCount: len(metaStrings(ev.Meta, "contacted_domains")) +
				len(metaStrings(ev.Meta, "contacted_ips")) +
				len(metaStrings(ev.Meta, "contacted_urls")),
		}
		// Keep the richest verdict if the same hash was detonated more than once
		// (e.g. a VT hit plus a sandbox run): prefer more AV hits + more IOCs.
		if prev, ok := out[h]; ok && prev.AVHits+prev.IOCCount >= vd.AVHits+vd.IOCCount {
			continue
		}
		out[h] = vd
	}
	return out
}

type capturesView struct {
	Enabled   bool
	Pcaps     []lootFile
	Sessions  []lootFile
	Artifacts []lootFile
	Creds     []credRow
	URLs      []harvestedURL // attacker-harvested URLs (dropper / C2), newest first
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

// harvestedURL is one attacker-referenced URL (a wget/curl dropper target,
// second-stage payload host, or C2) pulled from a shell session. URL is the raw
// value (used only by the click-through warning gate); Display is defanged so it
// can't be clicked or auto-linked by accident. The sensor never fetches these.
type harvestedURL struct {
	Time    time.Time
	Source  string
	Handler string
	URL     string // raw, for the gated open
	Display string // defanged (hxxp://…[.]…) for on-screen rendering
}

// defangURL renders a hostile URL unclickable/inert for display: http(s)→hxxp(s)
// and the scheme separator and dots neutralized. Keeps it readable without being
// a live link if the warning gate (JS) is bypassed.
func defangURL(u string) string {
	d := u
	d = strings.ReplaceAll(d, "https://", "hxxps[://]")
	d = strings.ReplaceAll(d, "http://", "hxxp[://]")
	d = strings.ReplaceAll(d, "ftp://", "fxp[://]")
	d = strings.ReplaceAll(d, ".", "[.]")
	return d
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
	// Join malware-detonation verdicts (VirusTotal / sandbox) onto the captured
	// artifacts by sha256, so the captures page shows the family + AV ratio.
	if len(v.Artifacts) > 0 {
		verdicts := detonationVerdicts(evs)
		for i := range v.Artifacts {
			if vd, ok := verdicts[artifactSHA256(v.Artifacts[i].Name)]; ok {
				a := &v.Artifacts[i]
				a.Verdict, a.MalFamily, a.AVLabel = vd.Verdict, vd.MalFamily, vd.AVLabel
				a.AVHits, a.AVTotal, a.DetSource, a.IOCCount = vd.AVHits, vd.AVTotal, vd.DetSource, vd.IOCCount
				a.VerdictEvent = vd.VerdictEvent
			}
		}
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
	// Attacker-harvested URLs (wget/curl droppers, C2) from the shell handlers.
	// Deduped across sources so a hammering botnet doesn't flood the table.
	urlSeen := map[string]struct{}{}
	for _, ev := range evs {
		for _, u := range metaStrings(ev.Meta, "harvested_urls") {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			key := ev.Source.IP + "\x00" + u
			if _, dup := urlSeen[key]; dup {
				continue
			}
			urlSeen[key] = struct{}{}
			v.URLs = append(v.URLs, harvestedURL{
				Time: ev.Time, Source: ev.Source.IP, Handler: ev.Handler,
				URL: u, Display: defangURL(u),
			})
		}
	}
	sort.Slice(v.URLs, func(i, j int) bool { return v.URLs[i].Time.After(v.URLs[j].Time) })
	if len(v.URLs) > 500 {
		v.URLs = v.URLs[:500]
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
	// Color-code each row by what it groups: the credential-type row and the
	// by-service row get distinct tints so the two are tellable apart at a
	// glance. The currently-selected chip in either row gets an "active" outline.
	base := "c-kind"
	if param == "service" {
		base = "c-service"
	}
	out := make([]counter, 0, len(items))
	for _, it := range items {
		cl := base
		if it.k == active {
			cl += " active" // outline the selected filter within its row
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
	// NoPayload: the credential summary reads event meta (extractCreds), never
	// the raw payload blob, so skip the payload column + per-row banner subquery
	// — the heavy part of the scan that made this page 500 at 100k+ events.
	if e, err := s.windowEvents(ctx, capturesWindow, s.scanCap(capturesScanMax)); err == nil {
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
