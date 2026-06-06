package ui

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fleet"
	"github.com/rom/tarpit-honeypot/internal/ioc"
	"github.com/rom/tarpit-honeypot/internal/portsvc"
)

// configCanvas is the "what is this sensor actually running" board for the
// /config page: every listener (port + service + mode) and every background
// collector (sniffers, network responders, enrichment, detection, forensics)
// with its active/inactive state. It's derived entirely from the effective
// config the sensor was wired with, so it always reflects the running shape.
type configCanvas struct {
	Listeners       []portCard       `json:"listeners"`
	TCPCount        int              `json:"tcp_count"`
	UDPCount        int              `json:"udp_count"`
	ListenerCount   int              `json:"listener_count"`
	Collectors      []collectorCard  `json:"collectors"`
	Groups          []collectorGroup `json:"-"` // collectors grouped by category, for rendering
	ActiveCollector int              `json:"active_collectors"`
	Interfaces      []netIfaceCard   `json:"interfaces"`
}

// collectorGroup buckets collectors by category for the rendered board.
type collectorGroup struct {
	Title string
	Items []collectorCard
}

// portCard is one listening socket on the board.
type portCard struct {
	Port      int    `json:"port"`
	PortLabel string `json:"port_label"` // numeric port, or the raw bind when unparseable
	Proto     string `json:"proto"`      // tcp | udp
	Service   string `json:"service"`    // IANA/honeypot service name for the port
	Handler   string `json:"handler"`
	Mode      string `json:"mode"` // drop | banner | tarpit
	Archetype string `json:"archetype,omitempty"`
	Capture   bool   `json:"capture"`
	TLS       bool   `json:"tls"`
	Severity  string `json:"severity,omitempty"`
	// Hit / Hits are set on the summary board only (markCanvasActivity): Hit is
	// true when this service saw at least one access/attempt in the window, and
	// Hits is the event count. The template tints a hit card so an operator can
	// see at a glance which services are actually being touched.
	Hit  bool `json:"hit,omitempty"`
	Hits int  `json:"hits,omitempty"`
}

// collectorCard is one background subsystem on the board.
type collectorCard struct {
	Name     string `json:"name"`
	Category string `json:"category"` // capture | responder | enrichment | detection | forensics | output
	Active   bool   `json:"active"`
	Detail   string `json:"detail,omitempty"`
}

// buildConfigCanvas projects the effective config into the board model.
func buildConfigCanvas(c *config.Config) configCanvas {
	var cv configCanvas
	if c == nil {
		return cv
	}

	for _, l := range c.Listeners {
		pc := portCard{
			Proto:     protoOrDefault(l.Proto),
			Handler:   l.Handler,
			Mode:      modeOrDefault(l.Mode),
			Archetype: l.Archetype,
			Capture:   l.Capture,
			Severity:  l.Severity,
		}
		if port, ok := bindPort(l.Bind); ok {
			pc.Port = port
			pc.PortLabel = strconv.Itoa(port)
			pc.Service = portsvc.Name(port)
		} else {
			pc.PortLabel = l.Bind
		}
		if pc.Service == "" {
			pc.Service = l.Handler
		}
		pc.TLS = isTLSListener(l)
		cv.Listeners = append(cv.Listeners, pc)
		if pc.Proto == "udp" {
			cv.UDPCount++
		} else {
			cv.TCPCount++
		}
	}
	// Stable order: TCP before UDP, then by port, then handler.
	sort.SliceStable(cv.Listeners, func(i, j int) bool {
		a, b := cv.Listeners[i], cv.Listeners[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto // tcp < udp
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Handler < b.Handler
	})
	cv.ListenerCount = len(cv.Listeners)

	cv.Collectors = buildCollectors(c)
	for _, col := range cv.Collectors {
		if col.Active {
			cv.ActiveCollector++
		}
	}
	cv.Groups = groupCollectors(cv.Collectors)
	cv.Interfaces = buildInterfaces(c)
	return cv
}

// groupCollectors buckets collectors into a fixed, human-ordered set of
// categories for the rendered board (skipping empty buckets).
func groupCollectors(cols []collectorCard) []collectorGroup {
	order := []struct{ key, title string }{
		{"capture", "Passive capture"},
		{"responder", "Network responders"},
		{"enrichment", "Enrichment"},
		{"detection", "Detection"},
		{"fleet", "Fleet / aggregation"},
		{"forensics", "Forensics"},
		{"output", "Output"},
	}
	var groups []collectorGroup
	for _, o := range order {
		var items []collectorCard
		for _, c := range cols {
			if c.Category == o.key {
				items = append(items, c)
			}
		}
		if len(items) > 0 {
			groups = append(groups, collectorGroup{Title: o.title, Items: items})
		}
	}
	return groups
}

// buildCollectors enumerates every background subsystem with its state, so the
// board shows both what's running and what's available-but-off.
func buildCollectors(c *config.Config) []collectorCard {
	var out []collectorCard
	add := func(name, cat string, active bool, detail string) {
		out = append(out, collectorCard{Name: name, Category: cat, Active: active, Detail: detail})
	}

	// --- passive capture ---
	snIface := c.Sniffer.Interface
	add("Packet sniffer (ARP/L2 scan)", "capture", c.Sniffer.Enabled, ifaceDetail(snIface))
	add("TCP stealth-scan detector", "capture", c.Sniffer.Enabled && c.Sniffer.TCPScan.Enabled, "NULL/FIN/Xmas + SYN flood")
	add("GOOSE monitor (IEC 61850)", "capture", c.Sniffer.Enabled && c.Sniffer.GOOSE.Enabled, "L2 multicast 0x88B8")
	dnsDetail := ""
	if c.DNS.Bind != "" {
		dnsDetail = "bind " + c.DNS.Bind
	}
	if c.DNS.AmplifierDetection.Enabled {
		dnsDetail = strings.TrimSpace(dnsDetail + " · amplifier-detection")
	}
	add("DNS canary listener", "capture", c.DNS.Enabled, dnsDetail)

	// --- network responders (per honeynet) ---
	arp, icmp, lldp, profinet, tun := collectResponders(c.Honeynets)
	add("ARP responder", "responder", len(arp) > 0, netsDetail(arp))
	add("ICMP echo responder", "responder", len(icmp) > 0, netsDetail(icmp))
	add("LLDP/CDP responder", "responder", len(lldp) > 0, netsDetail(lldp))
	add("PROFINET DCP responder", "responder", len(profinet) > 0, netsDetail(profinet))
	add("TUN device (L3 reachability)", "responder", len(tun) > 0, netsDetail(tun))

	// --- enrichment ---
	devDetail := "alert on new"
	if c.Devices.Learn {
		devDetail = "learn baseline"
	}
	add("Device inventory", "enrichment", c.Devices.Enabled, devDetail)
	geo := geoipDetail(c.Sensor.GeoIP)
	add("GeoIP enrichment", "enrichment", geo != "", geo)
	add("Reverse-DNS enrichment", "enrichment", c.Sensor.RDNS.Enabled, "")
	add("Threat-intel tagging", "enrichment", c.Sensor.ThreatIntel.Enabled && len(c.Sensor.ThreatIntel.Lists) > 0, threatIntelDetail(c.Sensor.ThreatIntel))
	add("Tor-exit tagging", "enrichment", c.Sensor.Tor.Enabled && c.Sensor.Tor.ExitFile != "", "")
	add("Network classification", "enrichment", c.Sensor.NetClass.Enabled, "bogon / cloud-hosting")
	add("MAC vendor (OUI)", "enrichment", true, ouiDetail(c.Sensor.OUIFile))

	// --- detection ---
	add("Risk scoring", "detection", c.Risk.Enabled, "")
	corrN := activeCorrelators(c.Correlate)
	add("Correlation engine", "detection", corrN > 0, plural(corrN, "detector"))
	canN := len(c.Canaries) + len(c.URLCanaries) + len(c.DNSCanaries)
	add("Canary tokens", "detection", canN > 0, canaryDetail(c))
	// Always-on per-source scan profiler (nmap timing template + tool
	// fingerprint + scan geometry); emits scananalysis:profile.
	add("Scan analysis", "detection", true, "nmap timing + tool fingerprint")
	add("Fuzzing/DoS classifier", "detection", true, "payload entropy + flood typing")
	add("Client fingerprinting", "detection", hasFingerprintListener(c.Listeners), "JA3/JA4/HASSH")

	// --- fleet / aggregation ---
	hasStore := c.UI.Enabled || hasSQLiteChannel(c.Channels)
	add("Fleet correlation", "fleet", c.Fleet.On(c.Ingest.Enabled), fleetCorrDetail(c))
	add("Fleet forwarding", "fleet", len(c.Forward) > 0, forwardDetail(c.Forward))
	add("Ingest endpoint (aggregator)", "fleet", c.Ingest.Enabled, ingestDetail(c.Ingest))
	add("Trust scoring", "fleet", c.Ingest.Trust.On(c.Ingest.Enabled), "score / quarantine child streams")
	add("Intel feed (serving)", "fleet", c.Fleet.On(c.Ingest.Enabled) && c.Ingest.Enabled && c.Fleet.ServingIntel(), "STIX/TAXII + /intel")
	add("Intel feed (subscribing)", "fleet", c.IntelFeed.Enabled, c.IntelFeed.URL)
	add("MISP push", "fleet", c.MISP.Enabled, c.MISP.URL)
	add("IOC store + ioc:* events", "fleet", c.IOC.On(hasStore), iocDetail(c.IOC))

	// --- forensics / output ---
	add("Payload capture", "forensics", c.Sensor.Payloads.Enabled, "")
	add("PCAP capture", "forensics", anyCaptureListener(c.Listeners), captureDetail(c.Listeners))
	add("Session recording", "forensics", c.Sensor.SessionRecording.Enabled, "telnet / ssh casts")
	add("Vuln/CVE emulation", "forensics", c.Sensor.VulnEmulation, "advertise unpatched versions")
	outN := outboundChannels(c.Channels)
	add("Event forwarding", "output", outN > 0, plural(outN, "outbound channel"))

	return out
}

// collectResponders returns, per responder kind, the honeynet IDs that enable it.
func collectResponders(nets []config.Honeynet) (arp, icmp, lldp, profinet, tun []string) {
	for _, n := range nets {
		id := n.ID
		if id == "" {
			id = n.CIDR
		}
		if n.ARP.Enabled {
			arp = append(arp, id)
		}
		if n.ICMP.Enabled {
			icmp = append(icmp, id)
		}
		if n.LLDP.Enabled {
			lldp = append(lldp, id)
		}
		if n.PROFINET.Enabled {
			profinet = append(profinet, id)
		}
		if n.TUN.Enabled {
			tun = append(tun, id)
		}
	}
	return
}

func activeCorrelators(c config.Correlate) int {
	flags := []bool{
		c.PortScan.Enabled, c.BruteForce.Enabled, c.SlowScan.Enabled,
		c.ICMPSweep.Enabled, c.PasswordSpray.Enabled, c.CredReuse.Enabled,
		c.PathEnum.Enabled, c.DNSEnum.Enabled, c.Beacon.Enabled,
		c.HostSweep.Enabled, c.ServiceSweep.Enabled, c.UARotation.Enabled,
		c.ExploitChain.Enabled, c.ICSControl.Enabled, c.CanaryTrip.Enabled,
		c.FingerprintReuse.Enabled, c.ProtocolViolation.Enabled,
		c.Exfil.Enabled, c.SessionFlood.Enabled,
	}
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func hasSQLiteChannel(chans []config.Channel) bool {
	for _, ch := range chans {
		if ch.Type == "sqlite" {
			return true
		}
	}
	return false
}

func fleetCorrDetail(c *config.Config) string {
	if !c.Fleet.On(c.Ingest.Enabled) {
		return ""
	}
	return plural(len(fleet.Catalog()), "cross-sensor detector")
}

func forwardDetail(ts []config.ForwardTarget) string {
	if len(ts) == 0 {
		return ""
	}
	full, rollup := 0, 0
	for _, t := range ts {
		if t.Mode == "rollup" {
			rollup++
		} else {
			full++
		}
	}
	d := plural(len(ts), "target")
	if rollup > 0 {
		d += fmt.Sprintf(" (%d full, %d rollup)", full, rollup)
	}
	return d
}

func ingestDetail(in config.IngestConfig) string {
	if !in.Enabled {
		return ""
	}
	return "bind " + in.Bind
}

func iocDetail(c config.IOCConfig) string {
	n := len(c.EmitTypes)
	if n == 0 {
		n = len(ioc.DefaultEmitTypes)
	}
	return plural(n, "emit type")
}

// threatIntelDetail summarizes the configured reputation lists.
func threatIntelDetail(ti config.ThreatIntel) string {
	if n := len(ti.Lists); n > 0 {
		return plural(n, "list")
	}
	return ""
}

// hasFingerprintListener reports whether any listener runs a handler the
// client-fingerprinting subsystem applies to (TLS-terminating or SSH).
func hasFingerprintListener(ls []config.Listener) bool {
	for _, l := range ls {
		switch l.Handler {
		case "https", "ssh", "ssh_interactive", "mqtt":
			return true
		}
		if isTLSListener(l) {
			return true
		}
	}
	return false
}

// anyCaptureListener reports whether any listener records a pcap.
func anyCaptureListener(ls []config.Listener) bool {
	for _, l := range ls {
		if l.Capture {
			return true
		}
	}
	return false
}

// captureDetail counts how many listeners have pcap capture on.
func captureDetail(ls []config.Listener) string {
	n := 0
	for _, l := range ls {
		if l.Capture {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return plural(n, "listener")
}

func outboundChannels(chs []config.Channel) int {
	n := 0
	for _, c := range chs {
		switch c.Type {
		case "", "stdout", "jsonlog", "sqlite":
			// local sinks, not outbound forwarding
		default:
			n++
		}
	}
	return n
}

func canaryDetail(c *config.Config) string {
	var parts []string
	if n := len(c.Canaries); n > 0 {
		parts = append(parts, plural(n, "file"))
	}
	if n := len(c.URLCanaries); n > 0 {
		parts = append(parts, plural(n, "URL"))
	}
	if n := len(c.DNSCanaries); n > 0 {
		parts = append(parts, plural(n, "DNS"))
	}
	return strings.Join(parts, " · ")
}

// ouiDetail notes whether MAC-vendor mapping uses a loaded full DB or the
// built-in table.
func ouiDetail(path string) string {
	if path != "" {
		return "IEEE OUI DB"
	}
	return "built-in table"
}

func geoipDetail(g config.GeoIP) string {
	var parts []string
	if g.CityDB != "" {
		parts = append(parts, "city")
	}
	if g.ASNDB != "" {
		parts = append(parts, "asn")
	}
	return strings.Join(parts, "+")
}

func ifaceDetail(iface string) string {
	if iface == "" {
		return "all interfaces"
	}
	return "iface " + iface
}

func netsDetail(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, ", ")
}

func plural(n int, unit string) string {
	if n == 0 {
		return ""
	}
	s := strconv.Itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

func protoOrDefault(p string) string {
	if strings.ToLower(p) == "udp" {
		return "udp"
	}
	return "tcp"
}

func modeOrDefault(m string) string {
	if m == "" {
		return "banner"
	}
	return m
}

// bindPort extracts the numeric port from a "host:port" bind, or ok=false.
func bindPort(bind string) (int, bool) {
	if bind == "" {
		return 0, false
	}
	_, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		// Maybe a bare ":port" or "port".
		if i := strings.LastIndexByte(bind, ':'); i >= 0 {
			portStr = bind[i+1:]
		} else {
			portStr = bind
		}
	}
	n, err := strconv.Atoi(portStr)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

// isTLSListener reports whether a listener terminates TLS (so the board can
// badge it). The https handler always does; winrm/redfish-style handlers do
// when bound to their TLS port.
func isTLSListener(l config.Listener) bool {
	switch l.Handler {
	case "https":
		return true
	}
	if port, ok := bindPort(l.Bind); ok {
		switch port {
		case 443, 8443, 5986, 8834:
			return true
		}
	}
	return false
}
