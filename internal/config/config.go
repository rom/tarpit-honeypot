package config

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	Sensor    Sensor     `yaml:"sensor"`
	UI        UI         `yaml:"ui"`
	Listeners []Listener `yaml:"listeners"`
	// Archeservices are role bundles (webserver, ftpserver, adserver, …)
	// that expand into Listeners at load time, combined with an archetype
	// for the software identity. See internal/archeservice.
	Archeservices []Archeservice `yaml:"archeservices"`
	Canaries      []Canary       `yaml:"canaries"`
	URLCanaries   []URLCanary    `yaml:"url_canaries"`
	DNS           DNS            `yaml:"dns"`
	DNSCanaries   []DNSCanary    `yaml:"dns_canaries"`
	Sniffer       Sniffer        `yaml:"sniffer"`
	Correlate     Correlate      `yaml:"correlate"`
	Honeynets     []Honeynet     `yaml:"honeynets"`
	Dedup         Dedup          `yaml:"dedup"`
	Allowlist     []string       `yaml:"allowlist"`
	Channels      []Channel      `yaml:"channels"`
	Routes        []Route        `yaml:"routes"`
	// Forward ships this node's events to parent aggregator node(s) for
	// fleet-wide correlation. Multiple targets fan out (HA, or a site SOC plus
	// a global hub). See internal/forward.
	Forward []ForwardTarget `yaml:"forward"`
	// Ingest accepts events forwarded by child nodes (this node acting as an
	// aggregator). Composes with Listeners + Forward, so a node can be a sensor,
	// a mid-tier aggregator, and forward upward all at once. See internal/ingest.
	Ingest IngestConfig `yaml:"ingest"`
	// Fleet is the cross-sensor correlator that runs over the merged (local +
	// ingested) stream, surfacing one source IP / ASN / fingerprint touching
	// several sensors within a window — a pattern no single sensor can see. It
	// defaults on wherever Ingest is enabled. See internal/fleet.
	Fleet FleetConfig `yaml:"fleet"`
	// IntelFeed subscribes this node to a parent's downward fleet-intel feed.
	// See internal/intel.
	IntelFeed IntelFeed `yaml:"intel_feed"`
	// MISP pushes the fleet's observed IOCs to a MISP instance. See internal/misp.
	MISP MISPConfig `yaml:"misp"`
	// IOC turns the indicators every event carries (IPs, fingerprints, hashes,
	// URLs, domains, CVEs, credentials, …) into a de-duplicated IOC store and
	// emits ioc:<type> events for the high-value first sightings. See internal/ioc.
	IOC IOCConfig `yaml:"ioc"`
	// SeverityOverrides re-map the reported severity of matching rule_ids
	// (an operator's local risk judgement). Applied in the router; the event
	// is marked as an override. See severity.go.
	SeverityOverrides []SeverityOverride `yaml:"severity_overrides"`
	Devices           Devices            `yaml:"devices"`
	Risk              RiskScoring        `yaml:"risk"`
	Interaction       Interaction        `yaml:"interaction"`

	// archeservicesExpanded guards expandArcheservices so it runs once even
	// if applyDefaults is invoked more than once on the same Config.
	archeservicesExpanded bool
}

// ForwardTarget is one parent aggregator this node ships events to.
type ForwardTarget struct {
	ID            string        `yaml:"id"`
	URL           string        `yaml:"url"`             // parent ingest endpoint, e.g. https://agg/ingest
	TokenEnv      string        `yaml:"token_env"`       // bearer token read from this env var
	HMACSecretEnv string        `yaml:"hmac_secret_env"` // optional body-signature key from this env var
	MinSeverity   string        `yaml:"min_severity"`    // low|medium|high|critical (empty = forward all)
	MaxBatch      int           `yaml:"max_batch"`       // flush after N events (default 500)
	MaxAge        time.Duration `yaml:"max_age"`         // flush at least this often (default 2s)
	QueueSize     int           `yaml:"queue_size"`      // in-memory buffer depth (default 4096)
	Timeout       time.Duration `yaml:"timeout"`         // per-POST timeout (default 10s)
	// Mode is "full" (default — ship every event) or "rollup" (ship one
	// periodic fleet:rollup summary instead — per-source/ASN/fingerprint/rule
	// counters — to keep upward volume sane at a higher tier). RollupInterval
	// sets the summary period (default 60s).
	Mode           string        `yaml:"mode"`
	RollupInterval time.Duration `yaml:"rollup_interval"`
	Enabled        *bool         `yaml:"enabled"` // nil/true = active; false = defined but off
}

// On reports whether the forward target is active.
func (f ForwardTarget) On() bool { return f.Enabled == nil || *f.Enabled }

// IngestConfig is the aggregator-side endpoint that accepts forwarded events.
type IngestConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Bind          string        `yaml:"bind"`            // host:port to accept batches on
	TokenEnv      string        `yaml:"token_env"`       // required bearer token (from env)
	HMACSecretEnv string        `yaml:"hmac_secret_env"` // optional body-signature verification
	TLSCert       string        `yaml:"tls_cert"`        // optional TLS
	TLSKey        string        `yaml:"tls_key"`
	MaxBodyMB     int           `yaml:"max_body_mb"`  // reject larger batches (default 32)
	MaxHops       int           `yaml:"max_hops"`     // drop events that traversed more nodes (default 8)
	DedupWindow   time.Duration `yaml:"dedup_window"` // sensor_id:id dedup TTL (default 10m)
	// Trust scores each child sensor's stream and can rate-limit / quarantine a
	// node whose stream looks fabricated. See internal/trust.
	Trust TrustConfig `yaml:"trust"`
}

// TrustConfig tunes per-sensor trust scoring + admission control at the ingest
// endpoint. On by default wherever ingest is enabled.
type TrustConfig struct {
	Enabled         *bool         `yaml:"enabled"`          // nil = on when ingest is enabled
	Window          time.Duration `yaml:"window"`           // counter window (default 5m)
	MinEvents       int           `yaml:"min_events"`       // min volume before scoring (default 50)
	AlertBelow      float64       `yaml:"alert_below"`      // fleet:sensor-untrusted below this score (default 0.5)
	QuarantineBelow float64       `yaml:"quarantine_below"` // refuse a sensor below this score (0 = never)
	RatePerSec      int           `yaml:"rate_per_sec"`     // per-sensor admission cap (0 = unlimited)
	Burst           int           `yaml:"burst"`            // token-bucket burst (default = rate_per_sec)
}

// On reports whether trust scoring should run. Defaults on wherever ingest is
// enabled (where there are child streams to score).
func (t TrustConfig) On(ingestEnabled bool) bool {
	if t.Enabled != nil {
		return *t.Enabled
	}
	return ingestEnabled
}

// FleetConfig tunes the cross-sensor correlator. The thresholds are "within a
// window"; zero values fall back to the internal/fleet defaults (window 1h,
// source_sensors 3, asn_sensors 5, fp_sensors 3, fp_sources 5, max_list 50).
type FleetConfig struct {
	// Enabled overrides the default: nil = auto (on when ingest is enabled),
	// true = force on, false = force off. Cross-sensor correlation is only
	// meaningful where events from several sensors converge, so an aggregator
	// gets it for free while a leaf sensor stays off unless forced on.
	Enabled       *bool         `yaml:"enabled"`
	Window        time.Duration `yaml:"window"`         // how long an identity's activity is remembered
	SourceSensors int           `yaml:"source_sensors"` // one source IP on >= N sensors -> alert
	ASNSensors    int           `yaml:"asn_sensors"`    // one ASN on >= N sensors -> alert
	FPSensors     int           `yaml:"fp_sensors"`     // one fingerprint on >= N sensors ...
	FPSources     int           `yaml:"fp_sources"`     // ... and >= M distinct sources -> alert
	// Shared-artifact campaigns (same hash / credential / CVE across sensors).
	PayloadSensors int `yaml:"payload_sensors"` // same malware artifact on >= N sensors
	CredSensors    int `yaml:"cred_sensors"`    // same credential pair on >= N sensors
	CVESensors     int `yaml:"cve_sensors"`     // same CVE on >= N sensors (exploit wave)
	// Coordinated distributed infrastructure (one source block, many IPs).
	SubnetSensors int `yaml:"subnet_sensors"` // a /24 (or /64) covering >= N sensors ...
	SubnetSources int `yaml:"subnet_sources"` // ... via >= M distinct IPs
	// Peer-relative outlier (a sensor far louder than its peers).
	OutlierMinEvents int     `yaml:"outlier_min_events"` // min high-sev events to be a candidate
	OutlierFactor    float64 `yaml:"outlier_factor"`     // must exceed this x the peer median
	OutlierMinPeers  int     `yaml:"outlier_min_peers"`  // need at least this many peers to compare
	// BroadCoverage is the sensors_hit/total fraction at/above which a
	// breadth/wave hit is "broad" internet background (downgraded to medium).
	BroadCoverage float64 `yaml:"broad_coverage"`
	// Scan trajectory (one source walking the address space across sensors).
	TrajectoryHits      int     `yaml:"trajectory_hits"`      // distinct destinations before evaluating
	TrajectorySensors   int     `yaml:"trajectory_sensors"`   // ... spanning >= N sensors
	TrajectoryMonotonic float64 `yaml:"trajectory_monotonic"` // fraction of steps moving one way
	// Synchronized burst (many sensors spiking at once).
	BurstWindow    time.Duration `yaml:"burst_window"`     // the short spike window
	BurstMinEvents int           `yaml:"burst_min_events"` // a sensor spikes at >= N events in the window
	BurstSensors   int           `yaml:"burst_sensors"`    // fire when >= N sensors spike together
	// First fleet contact (a brand-new ASN / fingerprint reaching the fleet).
	FirstContactSensors int           `yaml:"first_contact_sensors"` // novel identity must reach >= N sensors
	FirstSeenHorizon    time.Duration `yaml:"first_seen_horizon"`    // how long an identity is remembered as seen
	// Identity pivot (one actor across rotating IPs, linked by shared attributes).
	PivotSources int `yaml:"pivot_sources"` // >= N distinct IPs ...
	PivotSensors int `yaml:"pivot_sensors"` // ... across >= N sensors
	// Geo-distributed actor (one fingerprint / credential from many countries).
	GeoCountries int `yaml:"geo_countries"` // >= N distinct countries ...
	GeoSensors   int `yaml:"geo_sensors"`   // ... across >= N sensors
	// Target-profile match (the same multi-CVE playbook from distinct sources).
	ProfileCVEs    int `yaml:"profile_cves"`    // a playbook needs >= N CVEs to be a combination
	ProfileSources int `yaml:"profile_sources"` // >= N distinct sources sharing it ...
	ProfileSensors int `yaml:"profile_sensors"` // ... across >= N sensors
	// Honeytoken spread: same canary token tripped across the fleet.
	HoneytokenSensors int `yaml:"honeytoken_sensors"` // same token on >= N sensors
	// CVE emergence: a brand-new CVE reaching several sensors (n-day going live).
	CVEEmergenceSensors int `yaml:"cve_emergence_sensors"`
	// Cross-protocol actor: one source enumerating many services fleet-wide.
	CrossProtoHandlers int `yaml:"cross_proto_handlers"` // >= N distinct handlers ...
	CrossProtoSensors  int `yaml:"cross_proto_sensors"`  // ... across >= N sensors
	// Fingerprint-ASN spread: one fingerprint operated from many networks.
	FPASNs       int `yaml:"fp_asns"`        // one fingerprint from >= N distinct ASNs ...
	FPASNSensors int `yaml:"fp_asn_sensors"` // ... across >= N sensors
	// Threat-intel surge: flagged infra (threat-intel list / Tor) converging.
	ThreatSurgeSources int `yaml:"threat_surge_sources"` // >= N distinct flagged sources ...
	ThreatSurgeSensors int `yaml:"threat_surge_sensors"` // ... across >= N sensors
	// Tool campaign: the same identified attack tool across the fleet.
	ToolSensors int `yaml:"tool_sensors"` // one tool on >= N sensors ...
	ToolSources int `yaml:"tool_sources"` // ... from >= N distinct sources
	// C2 shared: the same harvested C2 / dropper URL across the fleet.
	C2Sensors int `yaml:"c2_sensors"` // one URL on >= N sensors
	// User-agent shared: the same HTTP User-Agent across the fleet.
	UASensors int `yaml:"ua_sensors"` // one UA on >= N sensors ...
	UASources int `yaml:"ua_sources"` // ... from >= N distinct sources
	// Tactic convergence: the same MITRE technique surging across the fleet.
	TacticSources int `yaml:"tactic_sources"` // >= N distinct sources using one technique ...
	TacticSensors int `yaml:"tactic_sensors"` // ... across >= N sensors
	// Recidivist network: an ASN returning across many time buckets.
	RecidivistBucket  time.Duration `yaml:"recidivist_bucket"`  // bucket size (default 24h)
	RecidivistWindows int           `yaml:"recidivist_windows"` // alert at >= N distinct buckets
	// Port campaign: a sudden fleet-wide focus on one destination port.
	PortCampaignSources int   `yaml:"port_campaign_sources"` // >= N distinct sources on one port ...
	PortCampaignSensors int   `yaml:"port_campaign_sensors"` // ... across >= N sensors
	PortCampaignExclude []int `yaml:"port_campaign_exclude"` // ubiquitous ports to ignore (default 22/80/443)
	// Credential spray: one username attacked with many passwords fleet-wide.
	CredSprayPasswords int `yaml:"cred_spray_passwords"` // >= N distinct passwords for one user ...
	CredSpraySensors   int `yaml:"cred_spray_sensors"`   // ... across >= N sensors
	// ASN-org campaign: one provider spanning several ASNs fleet-wide.
	AsnOrgASNs    int `yaml:"asn_org_asns"`    // >= N distinct ASNs under one org ...
	AsnOrgSensors int `yaml:"asn_org_sensors"` // ... across >= N sensors
	// Downward intel feedback (serving side). When this node both runs fleet
	// correlation and accepts ingest, it derives indicators from its fleet:*
	// findings and serves them at GET <ingest>/intel for child nodes to pull.
	ServeIntel *bool         `yaml:"serve_intel"` // nil/true = serve when fleet+ingest are on
	IntelTTL   time.Duration `yaml:"intel_ttl"`   // how long an indicator lingers (default 6h)
	IntelMax   int           `yaml:"intel_max"`   // cap per indicator set (default 10000)
	MaxList    int           `yaml:"max_list"`    // cap the sensor/source list in alert meta
}

// ServingIntel reports whether this node should derive + serve a fleet-intel
// feed. Defaults on wherever fleet correlation runs; the feed is only actually
// reachable when ingest is also enabled (it mounts on that endpoint).
func (f FleetConfig) ServingIntel() bool { return f.ServeIntel == nil || *f.ServeIntel }

// IntelFeed subscribes this node to a parent aggregator's downward fleet-intel
// feed: it polls the feed and hands the indicators to the enricher, so fleet
// knowledge tags this node's events (where tarpit / severity / risk / threat-
// intel already act). Independent of fleet correlation — a leaf sensor can
// subscribe without being an aggregator.
type IntelFeed struct {
	Enabled  bool          `yaml:"enabled"`
	URL      string        `yaml:"url"`       // parent feed endpoint, e.g. https://agg/intel
	TokenEnv string        `yaml:"token_env"` // bearer token read from this env var
	Poll     time.Duration `yaml:"poll"`      // poll interval (default 60s)
}

// IOCConfig controls the indicator-of-compromise store + ioc:<type> events.
// On by default wherever an event store exists.
type IOCConfig struct {
	Enabled   *bool    `yaml:"enabled"`    // nil = on when a store exists
	EmitTypes []string `yaml:"emit_types"` // first-sight types that emit ioc:<type> (default: high-value set)
}

// On reports whether IOC tracking should run (needs a store to persist into).
func (c IOCConfig) On(hasStore bool) bool {
	if c.Enabled != nil {
		return *c.Enabled && hasStore
	}
	return hasStore
}

// MISPConfig pushes the fleet's observed indicators (the intel store) to a MISP
// instance as periodic delta events. Meaningful only where fleet correlation
// runs (it's the IOC source).
type MISPConfig struct {
	Enabled      bool          `yaml:"enabled"`
	URL          string        `yaml:"url"`          // MISP base URL, e.g. https://misp.corp
	KeyEnv       string        `yaml:"key_env"`      // MISP auth key from this env var
	Interval     time.Duration `yaml:"interval"`     // push period (default 5m)
	EventInfo    string        `yaml:"event_info"`   // MISP event title
	Distribution string        `yaml:"distribution"` // MISP distribution level (default "0")
	ThreatLevel  string        `yaml:"threat_level"` // threat_level_id (default "2")
}

// On reports whether the fleet correlator should run. It defaults on for any
// node that accepts ingest (where cross-sensor correlation is meaningful); an
// explicit enabled value overrides that.
func (f FleetConfig) On(ingestEnabled bool) bool {
	if f.Enabled != nil {
		return *f.Enabled
	}
	return ingestEnabled
}

// Archeservice declares a service role to stand up. At load time it expands
// into one Listener per port the role exposes (see internal/archeservice),
// each carrying Archetype so the handlers answer with software/version
// strings consistent with that OS/device.
type Archeservice struct {
	ID        string `yaml:"id"`
	Role      string `yaml:"role"`      // webserver | ftpserver | adserver | …
	Archetype string `yaml:"archetype"` // optional OS/device identity
	Bind      string `yaml:"bind"`      // host/IP only — the role supplies ports
	Mode      string `yaml:"mode"`      // optional; default "banner"
	Severity  string `yaml:"severity"`  // optional; default per-listener
	Capture   bool   `yaml:"capture"`
	// VulnEmulation overrides sensor.vuln_emulation for the expanded
	// listeners. nil = inherit.
	VulnEmulation *bool `yaml:"vuln_emulation"`
}

// AlertsConfig configures operational alarms/notifications. Lifecycle
// (sensor:started/stopped) and health (sensor:health) are always on with
// sane defaults; first-seen and digests are opt-in.
type AlertsConfig struct {
	// FirstSeen emits source:first_seen the first time a source produces a
	// >= medium-severity event in this run (gated to keep it low-noise).
	FirstSeen bool `yaml:"first_seen"`
	// DigestInterval emits a periodic sensor:digest summary (top sources /
	// rules over the window). 0 = off.
	DigestInterval time.Duration `yaml:"digest_interval"`
	// DiskWarnPercent is the data_dir usage % above which sensor:health
	// warns. 0 -> default 90.
	DiskWarnPercent int `yaml:"disk_warn_percent"`
}

// RiskScoring configures the decaying per-source threat score. When
// enabled, every event adds severity/category-weighted points to its
// source; crossing a threshold emits risk:elevated / risk:high /
// risk:critical, and the top scorers surface in the web UI.
type RiskScoring struct {
	Enabled  bool          `yaml:"enabled"`
	HalfLife time.Duration `yaml:"half_life"` // score halves over this idle period
	Elevated float64       `yaml:"elevated"`
	High     float64       `yaml:"high"`
	Critical float64       `yaml:"critical"`
}

// Devices configures the learned-device inventory + "new device"
// alerting. When enabled, the sensor records every host it observes
// (from DHCP, the ARP sniffer, broadcast/multicast handlers, and the
// source IP of handled connections) and raises a device:new event for
// hosts that are neither allow-listed nor part of the learned baseline.
type Devices struct {
	Enabled bool `yaml:"enabled"`
	// Learn=true: the first run silently records a baseline; later
	// never-seen devices alert. Learn=false: strict allow-list mode —
	// every non-allow-listed device alerts on first sight.
	Learn bool `yaml:"learn"`
	// Allow is the list of known IPs / CIDRs / MACs that never alert.
	Allow []string `yaml:"allow"`
	// Severity of the device:new event (default high).
	Severity string `yaml:"severity"`
}

// Honeynet describes one artificial network. The sensor needs to actually
// receive traffic for the host IPs (the OS routes them to the sensor's
// network namespace, typically via `ip addr add`, NAT, or a TUN device).
// All fields except ID are optional — a deployment can configure metadata-
// only honeynets that only show up in DNS forward-resolution.
type Honeynet struct {
	ID       string               `yaml:"id"`
	CIDR     string               `yaml:"cidr"`
	Gateway  string               `yaml:"gateway"`
	DNS      string               `yaml:"dns"`
	Domain   string               `yaml:"domain"`
	Hosts    []HoneynetHost       `yaml:"hosts"`
	ARP      ARPResponderCfg      `yaml:"arp_responder"`
	ICMP     ICMPResponderCfg     `yaml:"icmp_responder"`
	LLDP     LLDPResponderCfg     `yaml:"lldp_responder"`
	TUN      TUNCfg               `yaml:"tun"`
	PROFINET ProfinetResponderCfg `yaml:"profinet_responder"`
}

// ProfinetResponderCfg makes virtual industrial hosts answer PROFINET-DCP
// Identify requests (EtherType 0x8892) so a PROFINET discovery scan
// (Siemens PRONETA / TIA Portal / nmap) enumerates the cell — and raises
// honeynet:profinet_dcp_identify on every request observed (ICS recon).
// Linux + CAP_NET_RAW only. Stations come from each host's archetype
// PROFINET device tree (SCALANCE-class), or the host itself for industrial
// archetypes without an explicit tree.
type ProfinetResponderCfg struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
	Severity  string `yaml:"severity"`
}

// LLDPResponderCfg makes virtual hosts appear in `lldpctl` / Cisco
// `show cdp neighbors` output on the L2 segment. The sensor opens
// an AF_PACKET socket (Linux + CAP_NET_RAW) and periodically emits
// LLDP frames (always) and optionally CDP frames (Cisco-specific)
// per honeynet host. Disabled by default — useful in industrial /
// enterprise networks where attackers walk LLDP to map the topology.
type LLDPResponderCfg struct {
	Enabled    bool   `yaml:"enabled"`
	Interface  string `yaml:"interface"`
	IntervalS  int    `yaml:"interval_s"`
	IncludeCDP bool   `yaml:"include_cdp"`
}

// TUNCfg opens a Linux TUN device the operator can route the honeynet
// CIDR into. The sensor responds to ICMP/ICMPv6 echo for any virtual
// host IP — making `nmap`-style reconnaissance see the network as alive
// without `ip addr add`.
//
// TCP is terminated by an embedded userspace stack (internal/tcpstack):
// a SYN to a host's configured service port completes a handshake with a
// SYN-ACK shaped to the host archetype's stack fingerprint (TTL, window,
// MSS, window-scale, SACK, timestamps, option order) and answers a single
// request/response from the archetype banners; unbound ports return RST
// and malformed/illegal packets are captured as events. No socket need be
// bound per virtual host.
type TUNCfg struct {
	Enabled bool   `yaml:"enabled"`
	Device  string `yaml:"device"`
	MTU     int    `yaml:"mtu"`
}

// ICMPResponderCfg makes virtual hosts respond to ICMP echo requests (ping)
// without `ip addr add`. Same Linux + AF_PACKET + CAP_NET_RAW constraints
// as the ARP responder; reuses the same MAC table.
type ICMPResponderCfg struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
}

// ARPResponderCfg makes the artificial network discoverable on the L2
// segment. When enabled (Linux only), the sensor opens an AF_PACKET socket
// on the named interface and replies to ARP requests for any virtual host
// IP with that host's derived MAC. Scanners running `arp-scan` see the
// network as fully populated without the operator running `ip addr add`
// for each virtual IP.
//
// Note: ARP responding alone does NOT route TCP / UDP traffic to the
// sensor. For the L4 dispatch you still need either `ip addr add`,
// iptables redirection, or a TUN-based adapter (the sensor only handles
// connections that actually arrive at one of its real sockets).
type ARPResponderCfg struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
}

type HoneynetHost struct {
	IP        string            `yaml:"ip"`
	Hostname  string            `yaml:"hostname"`
	OS        string            `yaml:"os"`
	Archetype string            `yaml:"archetype"`
	Services  []HoneynetService `yaml:"services"`
}

type HoneynetService struct {
	Port    int    `yaml:"port"`
	Handler string `yaml:"handler"`
	Banner  string `yaml:"banner"`
}

// DNS is the bind config for the canary DNS listener. The listener only
// starts when Enabled and at least one DNSCanary is configured (or
// AmplifierDetection is on).
type DNS struct {
	Enabled            bool         `yaml:"enabled"`
	Bind               string       `yaml:"bind"`
	AmplifierDetection DNSAmplifier `yaml:"amplifier_detection"`
}

// DNSAmplifier flags traffic shaped like amplifier reconnaissance.
type DNSAmplifier struct {
	Enabled  bool          `yaml:"enabled"`
	Window   time.Duration `yaml:"window"`
	Queries  int           `yaml:"queries"` // per-source threshold
	Severity string        `yaml:"severity"`
}

// URLCanary fires when any HTTP/HTTPS listener sees a request for the
// configured path. Use unguessable paths so legitimate scanning misses them.
type URLCanary struct {
	ID       string `yaml:"id"`
	Path     string `yaml:"path"` // exact path match, e.g. /backup/aws-prod.tar.gz
	Severity string `yaml:"severity"`
}

// DNSCanary fires when the DNS listener receives a query for the configured
// label or any subdomain underneath it. Use long random tokens.
type DNSCanary struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"` // e.g. "abc123.canary.example.com"
	Severity string `yaml:"severity"`
}

// Sniffer configures the optional Linux AF_PACKET sniffer that watches for
// ARP scans / unsolicited replies (L2) and, when TCPScan is enabled, TCP
// stealth scans seen on the wire (L3/L4) that never reach a listener.
type Sniffer struct {
	Enabled   bool       `yaml:"enabled"`
	Interface string     `yaml:"interface"` // empty = all
	ARPScan   ARPScanCfg `yaml:"arp_scan"`
	TCPScan   TCPScanCfg `yaml:"tcp_scan"`
	GOOSE     GOOSECfg   `yaml:"goose"`
	Severity  string     `yaml:"severity"`
}

// GOOSECfg controls passive IEC 61850 GOOSE detection. GOOSE is L2
// multicast (ethertype 0x88B8) carrying substation trip/status messages, so
// it's captured on a dedicated AF_PACKET socket. Each distinct
// (source MAC, gocbRef) is reported (rate-limited) — observing GOOSE on a
// segment, or a spoofed GOOSE stream, is high-signal in an OT environment.
type GOOSECfg struct {
	Enabled bool          `yaml:"enabled"`
	Window  time.Duration `yaml:"window"` // per-source dedup window (default 60s)
}

type ARPScanCfg struct {
	DistinctIPs int           `yaml:"distinct_ips"`
	Window      time.Duration `yaml:"window"`
}

// TCPScanCfg controls the packet-capture scan-detection layer. It opens a
// second AF_PACKET socket for inbound IPv4 and classifies TCP segments by
// flags: NULL/FIN/Xmas (stealth, flagged at StealthPorts distinct ports),
// SYN/ACK floods (flagged at DistinctPorts), and IP fragmentation. This
// catches scans the connection-level correlator never sees because no
// session is ever established (closed ports, dropped stealth probes).
type TCPScanCfg struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctPorts   int           `yaml:"distinct_ports"` // SYN/ACK volume threshold
	StealthPorts    int           `yaml:"stealth_ports"`  // NULL/FIN/Xmas threshold
	Window          time.Duration `yaml:"window"`
	DetectFragments bool          `yaml:"detect_fragments"`
}

type UI struct {
	Enabled      bool   `yaml:"enabled"`
	Bind         string `yaml:"bind"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	AuthTokenEnv string `yaml:"auth_token_env"`
	// AllowDeviceActions opts the otherwise read-only UI into the device
	// delete / whitelist write actions on the devices tab. Off by default;
	// even when true the actions require an auth token (auth_token_env), so
	// a tokenless loopback UI stays read-only.
	AllowDeviceActions bool `yaml:"allow_device_actions"`
	// RefreshSeconds sets the auto-refresh interval (HTML meta-refresh, since
	// the strict CSP forbids JS) for the live UI views. nil/omitted = 10s;
	// 0 = disabled. So the console updates during a scan without a manual
	// reload, while operators can still turn it off.
	RefreshSeconds *int `yaml:"refresh_seconds"`
}

// UIRefreshInterval returns the effective auto-refresh interval in seconds
// (default 10; a configured value <= 0 disables it).
func (u UI) UIRefreshInterval() int {
	if u.RefreshSeconds == nil {
		return 10
	}
	if *u.RefreshSeconds < 0 {
		return 0
	}
	return *u.RefreshSeconds
}

type Sensor struct {
	Name         string `yaml:"name"`
	DataDir      string `yaml:"data_dir"`
	DeploymentID string `yaml:"deployment_id"`
	DropUser     string `yaml:"drop_user"`
	DropGroup    string `yaml:"drop_group"`
	// Archetype is a deployment-default OS shape (e.g. "debian 12",
	// "Ubuntu 24.04 LTS"). When set, every handler that has an
	// archetype-aware banner (SSH, HTTP, FTP, Telnet, SMTP, MySQL)
	// reports a banner consistent with a stock install of that OS.
	// Per-listener archetype overrides this; per-host honeynet
	// archetype overrides both. Empty = fall back to the v1.0
	// deployment-id-keyed variant pool.
	Archetype string    `yaml:"archetype"`
	Disk      Disk      `yaml:"disk"`
	Jitter    Jitter    `yaml:"jitter"`
	Shutdown  Shutdown  `yaml:"shutdown"`
	TLSRotate TLSRotate `yaml:"tls_rotate"`
	GeoIP     GeoIP     `yaml:"geoip"`
	RDNS      RDNS      `yaml:"rdns"`
	// ThreatIntel tags source IPs that appear on operator-supplied
	// reputation lists. Tor flags Tor exit nodes. NetClass adds a coarse
	// built-in network classification (bogon / cloud-hosting). All three
	// are enrichment-only — they decorate events, never block.
	ThreatIntel ThreatIntel `yaml:"threat_intel"`
	Tor         TorIntel    `yaml:"tor"`
	NetClass    NetClass    `yaml:"net_class"`
	// OUIFile is the path to a MAC-vendor (OUI) database — the IEEE oui.csv
	// or a simple "prefix,vendor" CSV — used to map observed MAC addresses
	// to vendors. Unset = a small built-in table. Fetch the full DB with
	// scripts/fetch-enrichment.sh.
	OUIFile string `yaml:"oui_file"`
	// VulnEmulation, when true, makes banner-aware handlers advertise a
	// known-vulnerable version / patch-level for their service (so a
	// version scanner records an unpatched box) and recognize the
	// matching CVE exploit attempt. The honeypot never becomes actually
	// exploitable — it only presents the version and captures the
	// follow-up exploit. Per-listener `vuln_emulation` overrides this.
	// CVE exploit-attempt detection (cve:<id> events) runs regardless.
	VulnEmulation bool `yaml:"vuln_emulation"`
	// Payloads configures malware / shellcode / payload harvesting.
	Payloads Payloads `yaml:"payloads"`
	// Sandbox configures Linux kernel self-confinement (seccomp syscall
	// filter + Landlock filesystem restriction). Off by default; no-ops
	// on non-Linux.
	Sandbox Sandbox `yaml:"sandbox"`
	// Egress is the outbound allowlist. When enabled, the sensor's own
	// telemetry egress (sink / forward / export channels) is permitted to
	// exactly its configured destinations plus Allow, and every other
	// outbound connection is refused and reported (egress:denied) — so the
	// decoy can't be used as an SSRF pivot / relay / reflector / exfil
	// channel. Off by default (no behavior change until turned on).
	Egress EgressPolicy `yaml:"egress"`
	// SessionRecording records interactive shell sessions (telnet /
	// ssh_interactive) as asciinema v2 casts under <data_dir>/sessions/.
	SessionRecording SessionRecording `yaml:"session_recording"`
	// Alerts configures sensor lifecycle / health / first-seen / digest
	// operational events (separate from per-connection detection events).
	Alerts AlertsConfig `yaml:"alerts"`
	// Interfaces names the network interface(s) the sensor should use.
	// It supplies the default interface for the AF_PACKET layer — the
	// sniffer and the honeynet ARP/ICMP/LLDP/PROFINET responders — when
	// those sections don't set their own `interface`. Listeners that bind
	// to a wildcard host (0.0.0.0 / :: / empty) are expanded to bind on
	// each named interface's IP addresses. Empty = all interfaces.
	// Settable on the CLI with -i/--interface (repeatable), which
	// overrides this list.
	Interfaces []string `yaml:"interfaces"`
}

// EgressPolicy is the outbound allowlist. Configured channel destinations are
// always permitted when enabled; Allow adds endpoints not modeled as a channel
// (a central event collector, an IOC/threat-intel feed). Entries are a host, a
// host:port, or a CIDR.
type EgressPolicy struct {
	Enabled bool     `yaml:"enabled"`
	Allow   []string `yaml:"allow"`
	// Enforce additionally installs an OS-level nftables firewall (Linux, needs
	// the nft binary + CAP_NET_ADMIN at startup) that drops the sensor's
	// outbound packets to anything off the allowlist — the hard backstop under
	// the in-process guard, catching even a raw net.Dial. Implies Enabled.
	Enforce bool `yaml:"enforce"`
}

// On reports whether the in-process egress guard should be built (either the
// soft guard or the OS firewall is requested).
func (e EgressPolicy) On() bool { return e.Enabled || e.Enforce }

// SessionRecording configures interactive-session capture. Off by default.
type SessionRecording struct {
	Enabled bool `yaml:"enabled"`
	// MaxBytes caps a single cast (default 1 MiB).
	MaxBytes int `yaml:"max_bytes"`
	// MaxTotalMB caps the sessions directory with oldest-first rotation
	// (default 256 MB).
	MaxTotalMB int `yaml:"max_total_mb"`
}

// Sandbox configures kernel-enforced self-confinement applied after
// privileged setup + privilege drop. Linux-only; ignored elsewhere.
type Sandbox struct {
	// Seccomp installs a seccomp-bpf filter that denies syscalls the
	// honeypot never legitimately makes (execve/execveat, ptrace,
	// module loading, mount, kexec, process_vm_*, etc.) so a parser
	// 0-day can't spawn a shell or tamper with the kernel.
	Seccomp bool `yaml:"seccomp"`
	// Landlock restricts the process's filesystem access (Linux 5.13+):
	// read-only everywhere, writable only under data_dir + WritePaths.
	Landlock bool `yaml:"landlock"`
	// ReadPaths overrides the read-allowed roots (default ["/"]). Set
	// when you want to also deny reads outside an explicit list.
	ReadPaths []string `yaml:"read_paths"`
	// WritePaths grants write access to paths beyond data_dir (e.g. a
	// log file or socket dir outside the data directory).
	WritePaths []string `yaml:"write_paths"`
}

// Payloads configures capture of attacker-supplied binaries, shellcode,
// and exfil/ingress payloads to <data_dir>/payloads/. Off by default.
type Payloads struct {
	Enabled bool `yaml:"enabled"`
	// MaxBytes caps a single harvested artifact (default 1 MiB).
	MaxBytes int `yaml:"max_bytes"`
	// MaxTotalMB caps the payloads directory with oldest-first rotation
	// (default 256 MB).
	MaxTotalMB int `yaml:"max_total_mb"`
}

// GeoIP turns on country/city/ASN enrichment of source IPs using
// operator-supplied MaxMind GeoLite2 .mmdb files. Both paths optional —
// configure one or both. Loopback and RFC 1918 sources are not enriched.
type GeoIP struct {
	CityDB string `yaml:"city_db"`
	ASNDB  string `yaml:"asn_db"`
}

// RDNS enables synchronous reverse-DNS enrichment of source IPs with an
// LRU cache. The lookup is bounded by Timeout so a stalled resolver
// doesn't back up the bus.
type RDNS struct {
	Enabled   bool          `yaml:"enabled"`
	Timeout   time.Duration `yaml:"timeout"`
	CacheSize int           `yaml:"cache_size"`
}

// ThreatIntel tags source IPs found on operator-supplied reputation lists
// (one IP or CIDR per line; '#' comments allowed). Each list carries a
// label that lands in the event's threat_intel meta. Enrichment only.
type ThreatIntel struct {
	Enabled bool              `yaml:"enabled"`
	Lists   []ThreatIntelList `yaml:"lists"`
}

// ThreatIntelList is one labeled reputation list file.
type ThreatIntelList struct {
	Label string `yaml:"label"`
	File  string `yaml:"file"`
}

// TorIntel flags source IPs that appear in an operator-supplied Tor
// exit-node list (tor_exit=true on the event). Enrichment only.
type TorIntel struct {
	Enabled  bool   `yaml:"enabled"`
	ExitFile string `yaml:"exit_file"`
}

// NetClass enables the built-in, database-free network classification of
// public source IPs: "bogon" for reserved/martian ranges and "hosting"
// when the (GeoIP-ASN-derived) AS-org looks like datacenter/cloud infra.
type NetClass struct {
	Enabled bool `yaml:"enabled"`
}

// Jitter randomizes the latency of handler replies. min=max=0 disables.
type Jitter struct {
	Enabled bool `yaml:"enabled"`
	MinMS   int  `yaml:"min_ms"`
	MaxMS   int  `yaml:"max_ms"`
}

// Shutdown controls SIGTERM behavior. drain_timeout caps how long the
// sensor will wait for in-flight handlers before force-cancelling.
type Shutdown struct {
	DrainTimeout time.Duration `yaml:"drain_timeout"`
}

// TLSRotate controls automatic regeneration of the self-signed HTTPS
// handler certificate. 0 = never rotate (the v0.8 behavior).
type TLSRotate struct {
	Days int `yaml:"days"`
}

type Disk struct {
	JSONLogMB     int `yaml:"json_log_mb"`
	SQLiteMB      int `yaml:"sqlite_mb"`
	PcapMB        int `yaml:"pcap_mb"`        // total cap for the captures directory
	CaptureKB     int `yaml:"capture_kb"`     // per-session cap before truncation
	RetentionDays int `yaml:"retention_days"` // 0 = no time-based retention; otherwise events/files older than this are pruned
}

type Listener struct {
	ID            string        `yaml:"id"`
	Proto         string        `yaml:"proto"`   // tcp | udp
	Bind          string        `yaml:"bind"`    // host:port
	Mode          string        `yaml:"mode"`    // drop | banner | tarpit
	Handler       string        `yaml:"handler"` // raw | ssh | http | https | telnet | ftp | modbus | s7 | iec104 | mqtt
	Banner        string        `yaml:"banner"`
	Severity      string        `yaml:"severity"`
	ReadBytes     int           `yaml:"read_bytes"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	Capture       bool          `yaml:"capture"`        // record bidirectional bytes to <data_dir>/captures/<id>.pcap
	MaxConcurrent int           `yaml:"max_concurrent"` // per-listener accept cap; 0 = unlimited (TCP only)
	// Archetype overrides sensor.archetype for this listener. Empty
	// = inherit sensor.archetype. Useful when one sensor serves a
	// mix of OS-shaped traps on different ports.
	Archetype string `yaml:"archetype"`
	// AcceptCreds controls which login attempts a credential-capturing
	// handler (ftp_files, ...) treats as a success:
	//   ""/"none"  -> never accept (pure capture; default)
	//   "defaults" -> accept any known vendor-default credential
	//   "any"      -> accept anything (max engagement)
	AcceptCreds string `yaml:"accept_creds"`

	// VulnEmulation overrides sensor.vuln_emulation for this listener.
	// nil = inherit the sensor default; true/false force it on/off.
	VulnEmulation *bool `yaml:"vuln_emulation"`

	// Script is the path to a Lua dynamic-response script. Required when
	// handler is "lua"; the script drives the connection (read/write,
	// per-host personality, deterministic randomness, timers).
	Script string `yaml:"script"`

	// Scripted declaratively defines a fake request/response protocol.
	// Required (non-empty) when handler is "scripted".
	Scripted ScriptedProto `yaml:"scripted"`

	// Webapp turns an http / https listener into the full
	// fake-vulnerable web application (login + search + file download +
	// JSON API + the juicy paths scanners probe), detecting — never
	// executing — the web-attack families. Ignored by other handlers.
	Webapp bool `yaml:"webapp"`
	// WebappVariant selects the decoy web-app persona when Webapp is on:
	// "" / "generic" (PHP/MySQL intranet, default), "wordpress",
	// "phpmyadmin", or "jenkins". Unknown values fall back to generic.
	WebappVariant string `yaml:"webapp_variant"`

	HTTPS  HTTPS        `yaml:"https"`
	Tarpit Tarpit       `yaml:"tarpit"`
	SNMP   SNMPListener `yaml:"snmp"`
}

// SNMPListener configures the snmp UDP handler: which MIB subtrees the
// walkable MIB exposes, and per-source walk rate-limiting / tarpitting.
// Ignored by every other handler.
type SNMPListener struct {
	// MIBProfile selects the exposed subtrees: minimal | host | network |
	// full. Empty = "host" (system group + ifTable). network/full add the ip
	// group + the ipNetToMediaTable, making the honeynet topology walkable.
	MIBProfile string `yaml:"mib_profile"`
	// WalkRatePerMin caps GetNext/GetBulk varbinds answered per source IP per
	// minute (0 = unlimited). Over the cap a walk step is dropped — or
	// delayed by WalkTarpit when that's set, slowing a mass walker to a crawl.
	WalkRatePerMin int `yaml:"walk_rate_per_min"`
	// WalkTarpit, when > 0, delays each over-limit walk response by this long
	// instead of dropping it.
	WalkTarpit time.Duration `yaml:"walk_tarpit"`
}

// HTTPS configures the self-signed TLS cert the https handler presents.
// Each TLS-capable listener gets its own cert keyed by these fields so
// distinct services on the same host present distinct, believable
// endpoints (different subject, organization, key type, serial). When
// the subject fields are blank the handler derives deployment-unique
// defaults from sensor.deployment_id + the listener id, so two
// services on one sensor still look like two different machines.
type HTTPS struct {
	Hosts []string `yaml:"hosts"`
	// Subject fields. Blank = deployment+service-derived default.
	CN  string `yaml:"cn"`  // certificate Common Name
	Org string `yaml:"org"` // O= organization
	OU  string `yaml:"ou"`  // OU= organizational unit
	// KeyType selects the key algorithm: "ecdsa" (default, P-256) or
	// "rsa" (2048-bit). Mixing key types across services is a strong
	// "these are different machines" signal to a TLS-fingerprinting
	// scanner.
	KeyType string `yaml:"key_type"`
}

type Tarpit struct {
	// Strategy selects how the held connection behaves:
	//   sticky       - hold open, never read/write (kernel keepalive reaps)
	//   trickle      - one byte of trickle.text every byte_interval, cycling
	//   keepalive    - a NUL byte every keepalive.interval
	//   jitter       - trickle with a randomized interval [min,max]
	//   backoff      - trickle whose interval grows by factor up to max
	//   ssh_banner   - endlessh-style endless SSH preamble lines
	//   http_headers - endless HTTP response headers, never the blank line
	//   http_chunked - chunked HTTP body that never terminates
	//   echo         - dribble the attacker's own input back, delayed
	//   babble       - endless generated printable text
	//   zipbomb      - gzip decompression bomb (aggressive; opt-in only)
	//   zero_window  - LaBrea: clamp the TCP receive window toward zero
	Strategy     string `yaml:"strategy"`
	MaxPerSource int    `yaml:"max_per_source"`
	MaxTotal     int    `yaml:"max_total"`
	// Emulate, when true, runs the listener's protocol `handler:` to
	// completion FIRST (sending its real banner + capturing the
	// attacker's request), THEN applies the tarpit strategy on the same
	// connection. This turns any protocol emulator into a tarpit: the
	// scanner gets a believable SSH/HTTP/Modbus banner, then hangs. The
	// captured banner/request lands in the tarpit_start event.
	Emulate    bool          `yaml:"emulate"`
	Trickle    TrickleCfg    `yaml:"trickle"`
	Keepalive  KeepaliveCfg  `yaml:"keepalive"`
	Jitter     JitterCfg     `yaml:"jitter"`
	Backoff    BackoffCfg    `yaml:"backoff"`
	SSHBanner  SSHBannerCfg  `yaml:"ssh_banner"`
	HTTP       HTTPTarpitCfg `yaml:"http"`
	Echo       EchoCfg       `yaml:"echo"`
	Babble     BabbleCfg     `yaml:"babble"`
	ZipBomb    ZipBombCfg    `yaml:"zipbomb"`
	ZeroWindow ZeroWindowCfg `yaml:"zero_window"`
}

type TrickleCfg struct {
	Text         string        `yaml:"text"`
	ByteInterval time.Duration `yaml:"byte_interval"`
}

type KeepaliveCfg struct {
	Interval time.Duration `yaml:"interval"`
}

// JitterCfg configures the "jitter" strategy: trickle Text one byte at a time
// at a random interval drawn from [MinInterval, MaxInterval] each byte.
type JitterCfg struct {
	Text        string        `yaml:"text"`
	MinInterval time.Duration `yaml:"min_interval"`
	MaxInterval time.Duration `yaml:"max_interval"`
}

// BackoffCfg configures the "backoff" strategy: trickle Text starting at Start,
// multiplying the interval by Factor after each byte, capped at Max.
type BackoffCfg struct {
	Text   string        `yaml:"text"`
	Start  time.Duration `yaml:"start"`
	Max    time.Duration `yaml:"max"`
	Factor float64       `yaml:"factor"`
}

// SSHBannerCfg configures the "ssh_banner" (endlessh) strategy.
type SSHBannerCfg struct {
	LineInterval time.Duration `yaml:"line_interval"`
	MaxLineBytes int           `yaml:"max_line_bytes"`
}

// HTTPTarpitCfg is shared by the "http_headers" and "http_chunked" strategies.
type HTTPTarpitCfg struct {
	StatusLine     string        `yaml:"status_line"`
	HeaderInterval time.Duration `yaml:"header_interval"` // http_headers
	ChunkInterval  time.Duration `yaml:"chunk_interval"`  // http_chunked
	ChunkText      string        `yaml:"chunk_text"`      // http_chunked
}

// EchoCfg configures the "echo" strategy: delay between each echoed byte.
type EchoCfg struct {
	ByteInterval time.Duration `yaml:"byte_interval"`
}

// BabbleCfg configures the "babble" strategy: delay between generated bytes.
type BabbleCfg struct {
	ByteInterval time.Duration `yaml:"byte_interval"`
}

// ZipBombCfg configures the "zipbomb" strategy: an HTTP response advertising
// gzip Content-Encoding whose body inflates to DecompressedSize bytes from a
// highly compressible payload. Aggressive/retaliatory — opt-in only.
type ZipBombCfg struct {
	StatusLine       string        `yaml:"status_line"`
	DecompressedSize int64         `yaml:"decompressed_size"` // inflated byte count
	ChunkInterval    time.Duration `yaml:"chunk_interval"`    // pause between chunks (0 = blast)
}

// ZeroWindowCfg configures the "zero_window" (LaBrea) strategy: shrink the
// socket receive buffer to ReadBuffer bytes and never read, collapsing the
// advertised TCP window so a sending peer blocks indefinitely.
type ZeroWindowCfg struct {
	ReadBuffer int `yaml:"read_buffer"` // SO_RCVBUF target in bytes
}

// ScriptedProto declaratively defines a fake request/response protocol for
// the "scripted" handler — a believable custom TCP service without writing
// Lua. On connect the greeting (if any) is sent; then each client message
// is matched top-down against Rules and the first match's response is
// written. TCP-only: the three-way handshake rules out source-spoofed
// amplification, and per-response sizes are bounded at compile time.
type ScriptedProto struct {
	// Greeting is sent immediately on connect. Greeting uses text escapes
	// (\r \n \t \0 \xHH \\); GreetingHex is raw bytes as a hex string. Set
	// at most one.
	Greeting    string `yaml:"greeting"`
	GreetingHex string `yaml:"greeting_hex"`
	// MaxRounds caps request/response exchanges per connection (default 8,
	// hard ceiling 64).
	MaxRounds int `yaml:"max_rounds"`
	// Rules are evaluated top-down; the first match wins.
	Rules []ScriptedRule `yaml:"rules"`
	// Default / DefaultHex is the reply when no rule matches (same escape
	// rules as Greeting). Empty = send nothing.
	Default    string `yaml:"default"`
	DefaultHex string `yaml:"default_hex"`
}

// ScriptedRule is one match→respond rule in a ScriptedProto.
type ScriptedRule struct {
	// Match mode: prefix | contains | regex | hex_prefix | any, plus the
	// case-insensitive iprefix | icontains and suffix.
	Match string `yaml:"match"`
	// Value is the pattern: literal text (prefix/contains/suffix and their
	// i-variants), an RE2 regex (regex), or a lowercase hex string
	// (hex_prefix). Ignored for "any".
	Value string `yaml:"value"`
	// Respond / RespondHex is the reply written on a match (text escapes /
	// hex as in Greeting). Empty = respond with nothing (but still match,
	// so Anomaly/Close apply).
	Respond    string `yaml:"respond"`
	RespondHex string `yaml:"respond_hex"`
	// Anomaly, if set, is flagged on the event when this rule matches.
	Anomaly string `yaml:"anomaly"`
	// Close ends the connection after responding.
	Close bool `yaml:"close"`
	// Stage gates this rule: it only matches while the session is in this
	// stage (empty = any stage). SetStage transitions the session to a new
	// stage when the rule matches — together they model multi-step,
	// stateful protocols (e.g. an "auth" stage that must precede "command").
	Stage    string `yaml:"stage"`
	SetStage string `yaml:"set_stage"`
	// Capture, on a regex rule, records the first capture group into the
	// named credential meta field ("user" or "pass") so a custom auth
	// protocol feeds the attacker profile + default-credential matching.
	Capture string `yaml:"capture"`
}

// scriptedMaxResponse caps any single greeting/response/default payload so
// a misconfigured spec can't allocate unbounded memory or turn the service
// into an amplifier.
const scriptedMaxResponse = 64 * 1024

// scriptedValidModes is the set of accepted rule match modes.
var scriptedValidModes = map[string]bool{
	"prefix": true, "contains": true, "regex": true,
	"hex_prefix": true, "any": true,
	"iprefix": true, "icontains": true, "suffix": true,
}

// DecodeScriptedField resolves a (text, hex) field pair from a ScriptedProto
// into raw bytes. text supports \r \n \t \0 \xHH and \\ escapes; hexStr is
// straight hex. It is an error to set both. Used by both config validation
// and the scripted handler so decoding lives in one place.
func DecodeScriptedField(text, hexStr string) ([]byte, error) {
	if text != "" && hexStr != "" {
		return nil, fmt.Errorf("set only one of text / hex form")
	}
	if hexStr != "" {
		b, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil {
			return nil, fmt.Errorf("invalid hex: %w", err)
		}
		return b, nil
	}
	return decodeEscapes(text)
}

// decodeEscapes expands the small escape set scripted text fields support.
func decodeEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("dangling escape at end of %q", s)
		}
		switch s[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("\\x needs 2 hex digits in %q", s)
			}
			b, err := hex.DecodeString(s[i+1 : i+3])
			if err != nil {
				return nil, fmt.Errorf("bad \\x escape in %q: %w", s, err)
			}
			out = append(out, b[0])
			i += 2
		default:
			return nil, fmt.Errorf("unknown escape \\%c in %q", s[i], s)
		}
	}
	return out, nil
}

// Validate checks a ScriptedProto: a service must do something (greeting or
// at least one rule), each field must decode and stay within the size cap,
// every rule mode must be known, regexes must compile (RE2 — no
// catastrophic backtracking), and hex_prefix values must be valid hex.
func (p ScriptedProto) Validate() error {
	if len(p.Rules) == 0 && p.Greeting == "" && p.GreetingHex == "" {
		return fmt.Errorf("needs a greeting or at least one rule")
	}
	if p.MaxRounds < 0 || p.MaxRounds > 64 {
		return fmt.Errorf("max_rounds must be 0..64 (got %d)", p.MaxRounds)
	}
	greet, err := DecodeScriptedField(p.Greeting, p.GreetingHex)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if len(greet) > scriptedMaxResponse {
		return fmt.Errorf("greeting exceeds %d bytes", scriptedMaxResponse)
	}
	dflt, err := DecodeScriptedField(p.Default, p.DefaultHex)
	if err != nil {
		return fmt.Errorf("default: %w", err)
	}
	if len(dflt) > scriptedMaxResponse {
		return fmt.Errorf("default exceeds %d bytes", scriptedMaxResponse)
	}
	for i, r := range p.Rules {
		if !scriptedValidModes[r.Match] {
			return fmt.Errorf("rule[%d]: unknown match %q (prefix|contains|regex|hex_prefix|any)", i, r.Match)
		}
		if r.Match != "any" && r.Value == "" {
			return fmt.Errorf("rule[%d]: match %q requires a value", i, r.Match)
		}
		switch r.Match {
		case "regex":
			if _, err := regexp.Compile(r.Value); err != nil {
				return fmt.Errorf("rule[%d]: bad regex: %w", i, err)
			}
		case "hex_prefix":
			if _, err := hex.DecodeString(strings.TrimSpace(r.Value)); err != nil {
				return fmt.Errorf("rule[%d]: hex_prefix value not hex: %w", i, err)
			}
		}
		switch r.Capture {
		case "", "user", "pass":
		default:
			return fmt.Errorf("rule[%d]: capture must be user|pass (got %q)", i, r.Capture)
		}
		if r.Capture != "" && r.Match != "regex" {
			return fmt.Errorf("rule[%d]: capture requires match: regex (with a capture group)", i)
		}
		resp, err := DecodeScriptedField(r.Respond, r.RespondHex)
		if err != nil {
			return fmt.Errorf("rule[%d]: respond: %w", i, err)
		}
		if len(resp) > scriptedMaxResponse {
			return fmt.Errorf("rule[%d]: respond exceeds %d bytes", i, scriptedMaxResponse)
		}
	}
	return nil
}

type Canary struct {
	ID        string   `yaml:"id"`
	Path      string   `yaml:"path"`
	Recursive bool     `yaml:"recursive"`
	Events    []string `yaml:"events"` // write | remove | rename | create | chmod
	Severity  string   `yaml:"severity"`
}

type Correlate struct {
	PortScan      CorrPortScan      `yaml:"port_scan"`
	BruteForce    CorrBruteForce    `yaml:"brute_force"`
	SlowScan      CorrSlowScan      `yaml:"slow_scan"`
	ICMPSweep     CorrICMPSweep     `yaml:"icmp_sweep"`
	PasswordSpray CorrPasswordSpray `yaml:"password_spray"`
	CredReuse     CorrCredReuse     `yaml:"credential_reuse"`
	PathEnum      CorrPathEnum      `yaml:"path_enumeration"`
	DNSEnum       CorrDNSEnum       `yaml:"dns_enumeration"`
	Beacon        CorrBeacon        `yaml:"beacon"`
	// Additional opt-in correlators (all default-off; enable per deployment).
	HostSweep          CorrHostSweep          `yaml:"host_sweep"`
	ServiceSweep       CorrServiceSweep       `yaml:"service_sweep"`
	UARotation         CorrUARotation         `yaml:"ua_rotation"`
	ExploitChain       CorrExploitChain       `yaml:"exploit_chain"`
	ICSControl         CorrICSControl         `yaml:"ics_control"`
	CanaryTrip         CorrCanaryTrip         `yaml:"canary_trip"`
	FingerprintReuse   CorrFingerprintReuse   `yaml:"fingerprint_reuse"`
	ProtocolViolation  CorrProtocolViolation  `yaml:"protocol_violation"`
	Exfil              CorrExfil              `yaml:"exfil"`
	SessionFlood       CorrSessionFlood       `yaml:"session_flood"`
	LateralMovement    CorrLateralMovement    `yaml:"lateral_movement"`
	OTRecon            CorrOTRecon            `yaml:"ot_recon"`
	DataAccess         CorrDataAccess         `yaml:"data_access"`
	MalwareCampaign    CorrMalwareCampaign    `yaml:"malware_campaign"`
	Webshell           CorrWebshell           `yaml:"webshell"`
	ThreatIntelBurst   CorrThreatIntelBurst   `yaml:"threat_intel_burst"`
	GeoVelocity        CorrGeoVelocity        `yaml:"geo_velocity"`
	AmplificationProbe CorrAmplificationProbe `yaml:"amplification_probe"`
	DefaultCredSweep   CorrDefaultCredSweep   `yaml:"default_cred_sweep"`
	CVECampaign        CorrCVECampaign        `yaml:"cve_campaign"`
	DestructiveAction  CorrDestructiveAction  `yaml:"destructive_action"`
	HoneytokenSpread   CorrHoneytokenSpread   `yaml:"honeytoken_spread"`
	ToolRotation       CorrToolRotation       `yaml:"tool_rotation"`
	PLCProgramDownload CorrPLCProgramDownload `yaml:"plc_program_download"`
	ICSModeChange      CorrICSModeChange      `yaml:"ics_mode_change"`
	OTKillChain        CorrOTKillChain        `yaml:"ot_kill_chain"`
	RemoteToolSweep    CorrRemoteToolSweep    `yaml:"remote_tool_sweep"`
	OOBMgmtAccess      CorrOOBMgmtAccess      `yaml:"oob_mgmt_access"`
	RemoteExecCommand  CorrRemoteExecCommand  `yaml:"remote_exec_command"`
	TollFraud          CorrTollFraud          `yaml:"toll_fraud"`
	VoIPEnum           CorrVoIPEnum           `yaml:"voip_enum"`
	PBXControl         CorrPBXControl         `yaml:"pbx_control"`
}

// CorrTollFraud fires when one source makes several call-placement attempts
// (SIP INVITE scanning or AMI Originate) within a window — toll-fraud probing
// (premium / international call origination).
type CorrTollFraud struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrVoIPEnum fires when one source touches several DISTINCT VoIP protocols
// (SIP / SCCP / H.323 / IAX2 / AMI) within a window — telephony reconnaissance.
type CorrVoIPEnum struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrPBXControl fires when one source makes several administrative
// manager-interface interactions (AMI login / command) within a window — an
// attempt to take over the PBX.
type CorrPBXControl struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrRemoteToolSweep fires when one source probes several DISTINCT third-party
// remote-control / VDI tools (TeamViewer, AnyDesk, Radmin, DameWare, pcAnywhere,
// PCoIP, SPICE, ARD, …) within a window — hunting a remote-control foothold.
type CorrRemoteToolSweep struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctTools int           `yaml:"distinct_tools"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrOOBMgmtAccess fires when one source touches several DISTINCT out-of-band /
// lights-out management surfaces (IPMI/Redfish/iLO/iDRAC/AMT/console servers)
// within a window — targeting the management plane.
type CorrOOBMgmtAccess struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrRemoteExecCommand fires when a source executes a command over a cleartext
// remote-exec channel (rexec / rsh) — hands-on code execution in the clear.
type CorrRemoteExecCommand struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrPLCProgramDownload fires when a source downloads logic / firmware to a
// controller (SECS process-program, PCOM/FINS program write, an S7/CODESYS
// download) — the Stuxnet / Triton manipulation step, almost never legitimate
// against an exposed PLC.
type CorrPLCProgramDownload struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrICSModeChange fires when a source changes a controller's operating mode
// (RUN / STOP / PROGRAM) — a change-operating-mode / denial-of-control action.
type CorrICSModeChange struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrOTKillChain fires when one source both reconnoiters an ICS protocol and
// issues a control / program / mode command within the window — the
// discovery -> manipulation transition of the ICS kill chain.
type CorrOTKillChain struct {
	Enabled  bool          `yaml:"enabled"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrAmplificationProbe detects reflection/amplification DDoS scouting:
// one source touching several DISTINCT amplifier services (chargen / NTP /
// DNS / SSDP / memcached / SNMP / …) within a window — enumerating
// reflectors before a campaign.
type CorrAmplificationProbe struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrDefaultCredSweep detects an automated default-credential botnet
// (Mirai-class): one source tripping `default-credential-attempt` across
// several DISTINCT services within a window.
type CorrDefaultCredSweep struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrCVECampaign detects a mass-exploit / worm: the SAME CVE exploit
// signature arriving from several DISTINCT source IPs within a window (the
// inverse of exploit_chain, which is many CVEs from one source).
type CorrCVECampaign struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctSources int           `yaml:"distinct_sources"`
	Window          time.Duration `yaml:"window"`
	Severity        string        `yaml:"severity"`
}

// CorrDestructiveAction fires when one source performs several data-
// destruction operations (redis FLUSHALL, memcached flush_all, a printer
// filesystem format, an FTP delete) within a window — a hands-on-keyboard
// impact action that warrants immediate escalation.
type CorrDestructiveAction struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrHoneytokenSpread fires when the SAME canary token (URL / DNS / file /
// credential) is tripped by several DISTINCT source IPs within a window — the
// planted token has leaked and is being used broadly.
type CorrHoneytokenSpread struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctSources int           `yaml:"distinct_sources"`
	Window          time.Duration `yaml:"window"`
	Severity        string        `yaml:"severity"`
}

// CorrToolRotation fires when one source is identified running several
// DISTINCT attack tools / scanners within a window — the tool analogue of
// ua_rotation, marking a determined adversary cycling tooling.
type CorrToolRotation struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctTools int           `yaml:"distinct_tools"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrThreatIntelBurst fires when one source whose events enrichment tagged
// as known-bad infrastructure (threat-intel list member or Tor exit)
// produces several events within a window — sustained activity from a
// flagged origin, whatever service it touches. Needs the enrichment layer
// (threat_intel / tor) configured.
type CorrThreatIntelBurst struct {
	Enabled  bool          `yaml:"enabled"`
	Events   int           `yaml:"events"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrGeoVelocity fires when the SAME credential pair is tried from two or
// more DISTINCT GeoIP countries within a window — "impossible travel" /
// credential stuffing across geographies. Needs GeoIP enrichment.
type CorrGeoVelocity struct {
	Enabled           bool          `yaml:"enabled"`
	DistinctCountries int           `yaml:"distinct_countries"`
	Window            time.Duration `yaml:"window"`
	Severity          string        `yaml:"severity"`
}

// CorrLateralMovement detects one source probing many DISTINCT lateral-
// movement services (RDP, SMB, WinRM, SSH, VNC, MSRPC) within a window —
// the breadth signature of an attacker hunting a pivot host.
type CorrLateralMovement struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrOTRecon detects an ICS/OT reconnaissance sweep: one source touching
// many DISTINCT industrial-protocol handlers (Modbus, S7, DNP3, EtherNet/IP,
// …) within a window — mapping a control network.
type CorrOTRecon struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrDataAccess detects bulk data-store collection: repeated data-access
// events (Mongo/Elasticsearch/Redis/memcached reads, SMB share listing)
// from one source within a window.
type CorrDataAccess struct {
	Enabled  bool          `yaml:"enabled"`
	Attempts int           `yaml:"attempts"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrMalwareCampaign detects repeated ingress-tool transfers: several
// malware:capture events (distinct droppers/payloads) from one source.
type CorrMalwareCampaign struct {
	Enabled  bool          `yaml:"enabled"`
	Captures int           `yaml:"captures"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrWebshell detects sustained web-shell interaction: repeated web-shell
// access / command events from one source within a window.
type CorrWebshell struct {
	Enabled  bool          `yaml:"enabled"`
	Attempts int           `yaml:"attempts"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrHostSweep detects a horizontal network sweep: one source touching
// many DISTINCT destination (honeynet) hosts within a window — the breadth
// axis the vertical port_scan correlator can't see. Complements icmp_sweep
// (which keys on ICMP) by catching TCP/UDP host discovery.
type CorrHostSweep struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctHosts int           `yaml:"distinct_hosts"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrServiceSweep detects cross-protocol reconnaissance: one source
// interacting with many DISTINCT service handlers (ssh, http, modbus, smb,
// …) within a window — a service-discovery pass rather than a port count.
type CorrServiceSweep struct {
	Enabled          bool          `yaml:"enabled"`
	DistinctServices int           `yaml:"distinct_services"`
	Window           time.Duration `yaml:"window"`
	Severity         string        `yaml:"severity"`
}

// CorrUARotation detects User-Agent rotation: one source presenting many
// DISTINCT HTTP User-Agent strings within a window — scanner evasion / a
// tool cycling identities that per-request fingerprinting misses.
type CorrUARotation struct {
	Enabled        bool          `yaml:"enabled"`
	DistinctAgents int           `yaml:"distinct_agents"`
	Window         time.Duration `yaml:"window"`
	Severity       string        `yaml:"severity"`
}

// CorrExploitChain detects one source attempting many DISTINCT CVEs within
// a window — a vuln-chaining / mass-exploit run, a much stronger signal
// than a single cve:* hit.
type CorrExploitChain struct {
	Enabled      bool          `yaml:"enabled"`
	DistinctCVEs int           `yaml:"distinct_cves"`
	Window       time.Duration `yaml:"window"`
	Severity     string        `yaml:"severity"`
}

// CorrICSControl detects OT manipulation: repeated control / write / restart
// commands to industrial-protocol handlers (Modbus write, BACnet
// WriteProperty, DNP3 operate, …) from one source within a window — the
// "manipulation of control" stage of an ICS attack.
type CorrICSControl struct {
	Enabled  bool          `yaml:"enabled"`
	Attempts int           `yaml:"attempts"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrCanaryTrip detects one source tripping many DISTINCT canary tokens /
// honeyfile URLs within a window — systematic decoy harvesting, an
// unambiguous hands-on-keyboard signal.
type CorrCanaryTrip struct {
	Enabled        bool          `yaml:"enabled"`
	DistinctTokens int           `yaml:"distinct_tokens"`
	Window         time.Duration `yaml:"window"`
	Severity       string        `yaml:"severity"`
}

// CorrFingerprintReuse detects the same client fingerprint (JA3 / JA4 /
// HASSH) arriving from many DISTINCT source IPs within a window — a botnet
// or shared tool fronted by a rotating-IP pool.
type CorrFingerprintReuse struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctSources int           `yaml:"distinct_sources"`
	Window          time.Duration `yaml:"window"`
	Severity        string        `yaml:"severity"`
}

// CorrProtocolViolation detects fuzzing: one source tripping many DISTINCT
// protocol-misuse anomaly markers within a window (malformed frames,
// out-of-spec methods) — the signature of a protocol fuzzer.
type CorrProtocolViolation struct {
	Enabled           bool          `yaml:"enabled"`
	DistinctAnomalies int           `yaml:"distinct_anomalies"`
	Window            time.Duration `yaml:"window"`
	Severity          string        `yaml:"severity"`
}

// CorrExfil detects bulk inbound transfer: cumulative request bytes from one
// source crossing a byte threshold within a window — data staging / a large
// upload (malware drop, oversized POST) against the decoy.
type CorrExfil struct {
	Enabled  bool          `yaml:"enabled"`
	Bytes    int64         `yaml:"bytes"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// CorrSessionFlood detects volumetric abuse: one source opening many
// connections within a short window regardless of port spread — a
// connection flood / DoS probe / aggressive tarpit engagement.
type CorrSessionFlood struct {
	Enabled     bool          `yaml:"enabled"`
	Connections int           `yaml:"connections"`
	Window      time.Duration `yaml:"window"`
	Severity    string        `yaml:"severity"`
}

// CorrBeacon detects C2 beaconing: repeated, regularly-spaced contact from
// one source. After MinHits events it measures the inter-arrival jitter
// (stddev/mean as a percentage); a low jitter (<= MaxJitterPct) over a
// non-trivial mean interval is the periodic call-home pattern of a beacon.
type CorrBeacon struct {
	Enabled      bool          `yaml:"enabled"`
	MinHits      int           `yaml:"min_hits"`
	MaxJitterPct int           `yaml:"max_jitter_pct"`
	Window       time.Duration `yaml:"window"`
	Severity     string        `yaml:"severity"`
}

// CorrPathEnum detects HTTP content discovery: one source requesting many
// DISTINCT URL paths within a window (dirbusting / forced browsing), which
// per-request tool fingerprinting can miss when the UA is spoofed.
type CorrPathEnum struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctPaths int           `yaml:"distinct_paths"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrDNSEnum detects DNS name enumeration: one source querying many
// DISTINCT names within a window — subdomain brute force, an NXDOMAIN flood,
// or DGA churn.
type CorrDNSEnum struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctNames int           `yaml:"distinct_names"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrPasswordSpray detects password spraying: one source trying many
// DISTINCT usernames (low attempts each) within a window — the inverse of
// brute force (many attempts against one account).
type CorrPasswordSpray struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctUsers int           `yaml:"distinct_users"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

// CorrCredReuse detects the same credential pair attempted from many
// DISTINCT source IPs within a window — a shared credential list / botnet
// (credential stuffing).
type CorrCredReuse struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctSources int           `yaml:"distinct_sources"`
	Window          time.Duration `yaml:"window"`
	Severity        string        `yaml:"severity"`
}

// CorrICMPSweep detects an ICMP ping sweep: one source touching N
// distinct destination IPs via ICMP (echo, timestamp, address-mask)
// inside a window. Distinct from port_scan, which keys on ports — a
// ping sweep maps the live-host inventory of a subnet and is a
// classic discovery-phase precursor.
type CorrICMPSweep struct {
	Enabled     bool          `yaml:"enabled"`
	DistinctIPs int           `yaml:"distinct_ips"`
	Window      time.Duration `yaml:"window"`
	Severity    string        `yaml:"severity"`
}

// CorrSlowScan detects scanning over long windows. Default thresholds
// (10 distinct ports in 24h) flag a "one port per hour"-style scan that
// the regular fixed-window port_scan correlator cannot.
type CorrSlowScan struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctPorts int           `yaml:"distinct_ports"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

type CorrPortScan struct {
	Enabled       bool          `yaml:"enabled"`
	DistinctPorts int           `yaml:"distinct_ports"`
	Window        time.Duration `yaml:"window"`
	Severity      string        `yaml:"severity"`
}

type CorrBruteForce struct {
	Enabled  bool          `yaml:"enabled"`
	Attempts int           `yaml:"attempts"`
	Window   time.Duration `yaml:"window"`
	PerPort  bool          `yaml:"per_port"`
	Severity string        `yaml:"severity"`
}

type Dedup struct {
	DefaultWindow time.Duration `yaml:"default_window"`
}

type Channel struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"` // stdout | jsonlog | sqlite | webhook | smtp | syslog | twilio | sns | snmptrap
	// Enabled gates the channel. Omitted (nil) or true = active; false =
	// defined but skipped (not built, not validated for type-specifics) —
	// so an outbound sink that needs external infra (an MQTT broker, a
	// webhook secret, a SIEM host) can ship in a config but stay off until
	// the operator turns it on. Routes referencing a disabled channel are
	// simply not delivered there.
	Enabled         *bool  `yaml:"enabled"`
	Format          string `yaml:"format"` // json (default) | cef | leef | ocsf
	MinSeverity     string `yaml:"min_severity"`
	RateLimitPerMin int    `yaml:"rate_limit_per_min"`

	// webhook
	URL           string        `yaml:"url"`
	URLEnv        string        `yaml:"url_env"` // read URL from this env var (keeps secrets/webhook tokens out of YAML)
	HMACSecretEnv string        `yaml:"hmac_secret_env"`
	Timeout       time.Duration `yaml:"timeout"`

	// smtp + snmptrap share Host/Port
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	StartTLS    bool     `yaml:"starttls"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`

	// syslog
	Network string `yaml:"network"` // tcp | udp | unix | local
	Address string `yaml:"address"`
	Tag     string `yaml:"tag"`

	// twilio
	AccountSIDEnv string `yaml:"account_sid_env"`
	AuthTokenEnv  string `yaml:"auth_token_env"`

	// aws sns
	TopicARN        string `yaml:"topic_arn"`
	Region          string `yaml:"region"`
	AccessKeyEnv    string `yaml:"access_key_env"`
	SecretKeyEnv    string `yaml:"secret_key_env"`
	SessionTokenEnv string `yaml:"session_token_env"`

	// snmptrap. CommunityEnv (preferred) reads the community string from an
	// env var so the write credential isn't stored in the YAML / shown by
	// show-config; inline Community is still honored for convenience.
	Community     string `yaml:"community"`
	CommunityEnv  string `yaml:"community_env"`
	EnterpriseOID string `yaml:"enterprise_oid"`

	// mqtt
	Topic  string `yaml:"topic"`
	QoS    int    `yaml:"qos"`
	Retain bool   `yaml:"retain"`

	// TLS options shared by stream sinks that dial over TLS (syslog
	// network=tls, mqtt tls:// brokers). Default = verify against the
	// system roots.
	TLSInsecure   bool   `yaml:"tls_insecure"`    // skip cert verification (lab brokers only)
	CACertFile    string `yaml:"ca_cert_file"`    // PEM bundle to verify the server against
	TLSServerName string `yaml:"tls_server_name"` // SNI / verify name override
}

// On reports whether the channel is enabled. Default (Enabled nil) is on,
// so existing configs are unaffected; set `enabled: false` to keep a
// channel defined but skipped.
func (c Channel) On() bool { return c.Enabled == nil || *c.Enabled }

type Route struct {
	Match    Match    `yaml:"match"`
	Channels []string `yaml:"channels"`
}

// Match is the route predicate. All non-empty fields must hold for the
// route to fire on a given event. Fields are AND-ed together; configure
// multiple routes for OR semantics.
type Match struct {
	Severity   string `yaml:"severity"`    // ">=low", "<high", "=critical"
	Honeynet   string `yaml:"honeynet"`    // exact match on event.meta.honeynet (the network id)
	HoneynetOS string `yaml:"honeynet_os"` // exact match on event.meta.honeynet_os
	RuleID     string `yaml:"rule_id"`     // exact match on event.rule_id
}
