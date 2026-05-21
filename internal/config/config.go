package config

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	Sensor      Sensor      `yaml:"sensor"`
	UI          UI          `yaml:"ui"`
	Listeners   []Listener  `yaml:"listeners"`
	Canaries    []Canary    `yaml:"canaries"`
	URLCanaries []URLCanary `yaml:"url_canaries"`
	DNS         DNS         `yaml:"dns"`
	DNSCanaries []DNSCanary `yaml:"dns_canaries"`
	Sniffer     Sniffer     `yaml:"sniffer"`
	Correlate   Correlate   `yaml:"correlate"`
	Honeynets   []Honeynet  `yaml:"honeynets"`
	Dedup       Dedup       `yaml:"dedup"`
	Allowlist   []string    `yaml:"allowlist"`
	Channels    []Channel   `yaml:"channels"`
	Routes      []Route     `yaml:"routes"`
	Devices     Devices     `yaml:"devices"`
	Risk        RiskScoring `yaml:"risk"`
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
// host IP and sends TCP RST for unbound ports — making `nmap`-style
// reconnaissance see the network as alive without `ip addr add`.
//
// For real TCP termination through the TUN we still need a userspace
// TCP stack — see "What's NOT in v1.5" in the README. Today this is
// L3 discovery only.
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
	Severity  string     `yaml:"severity"`
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

	HTTPS  HTTPS  `yaml:"https"`
	Tarpit Tarpit `yaml:"tarpit"`
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
	Strategy     string `yaml:"strategy"` // sticky | trickle | keepalive
	MaxPerSource int    `yaml:"max_per_source"`
	MaxTotal     int    `yaml:"max_total"`
	// Emulate, when true, runs the listener's protocol `handler:` to
	// completion FIRST (sending its real banner + capturing the
	// attacker's request), THEN applies the tarpit strategy on the same
	// connection. This turns any protocol emulator into a tarpit: the
	// scanner gets a believable SSH/HTTP/Modbus banner, then hangs. The
	// captured banner/request lands in the tarpit_start event.
	Emulate   bool         `yaml:"emulate"`
	Trickle   TrickleCfg   `yaml:"trickle"`
	Keepalive KeepaliveCfg `yaml:"keepalive"`
}

type TrickleCfg struct {
	Text         string        `yaml:"text"`
	ByteInterval time.Duration `yaml:"byte_interval"`
}

type KeepaliveCfg struct {
	Interval time.Duration `yaml:"interval"`
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
	// Match mode: prefix | contains | regex | hex_prefix | any.
	Match string `yaml:"match"`
	// Value is the pattern: literal text (prefix/contains), an RE2 regex
	// (regex), or a lowercase hex string (hex_prefix). Ignored for "any".
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
}

// scriptedMaxResponse caps any single greeting/response/default payload so
// a misconfigured spec can't allocate unbounded memory or turn the service
// into an amplifier.
const scriptedMaxResponse = 64 * 1024

// scriptedValidModes is the set of accepted rule match modes.
var scriptedValidModes = map[string]bool{
	"prefix": true, "contains": true, "regex": true,
	"hex_prefix": true, "any": true,
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
	ID              string `yaml:"id"`
	Type            string `yaml:"type"`   // stdout | jsonlog | sqlite | webhook | smtp | syslog | twilio | sns | snmptrap
	Format          string `yaml:"format"` // json (default) | cef | leef | ocsf
	MinSeverity     string `yaml:"min_severity"`
	RateLimitPerMin int    `yaml:"rate_limit_per_min"`

	// webhook
	URL           string        `yaml:"url"`
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
}

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
