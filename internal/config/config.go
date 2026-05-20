package config

import "time"

type Config struct {
	Sensor       Sensor       `yaml:"sensor"`
	UI           UI           `yaml:"ui"`
	Listeners    []Listener   `yaml:"listeners"`
	Canaries     []Canary     `yaml:"canaries"`
	URLCanaries  []URLCanary  `yaml:"url_canaries"`
	DNS          DNS          `yaml:"dns"`
	DNSCanaries  []DNSCanary  `yaml:"dns_canaries"`
	Sniffer      Sniffer      `yaml:"sniffer"`
	Correlate    Correlate    `yaml:"correlate"`
	Honeynets    []Honeynet   `yaml:"honeynets"`
	Dedup        Dedup        `yaml:"dedup"`
	Allowlist    []string     `yaml:"allowlist"`
	Channels     []Channel    `yaml:"channels"`
	Routes       []Route      `yaml:"routes"`
}

// Honeynet describes one artificial network. The sensor needs to actually
// receive traffic for the host IPs (the OS routes them to the sensor's
// network namespace, typically via `ip addr add`, NAT, or a TUN device).
// All fields except ID are optional — a deployment can configure metadata-
// only honeynets that only show up in DNS forward-resolution.
type Honeynet struct {
	ID      string             `yaml:"id"`
	CIDR    string             `yaml:"cidr"`
	Gateway string             `yaml:"gateway"`
	DNS     string             `yaml:"dns"`
	Domain  string             `yaml:"domain"`
	Hosts   []HoneynetHost     `yaml:"hosts"`
	ARP     ARPResponderCfg    `yaml:"arp_responder"`
	ICMP    ICMPResponderCfg   `yaml:"icmp_responder"`
	LLDP    LLDPResponderCfg   `yaml:"lldp_responder"`
	TUN     TUNCfg             `yaml:"tun"`
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
	Enabled            bool             `yaml:"enabled"`
	Bind               string           `yaml:"bind"`
	AmplifierDetection DNSAmplifier     `yaml:"amplifier_detection"`
}

// DNSAmplifier flags traffic shaped like amplifier reconnaissance.
type DNSAmplifier struct {
	Enabled  bool          `yaml:"enabled"`
	Window   time.Duration `yaml:"window"`
	Queries  int           `yaml:"queries"`   // per-source threshold
	Severity string        `yaml:"severity"`
}

// URLCanary fires when any HTTP/HTTPS listener sees a request for the
// configured path. Use unguessable paths so legitimate scanning misses them.
type URLCanary struct {
	ID       string `yaml:"id"`
	Path     string `yaml:"path"`      // exact path match, e.g. /backup/aws-prod.tar.gz
	Severity string `yaml:"severity"`
}

// DNSCanary fires when the DNS listener receives a query for the configured
// label or any subdomain underneath it. Use long random tokens.
type DNSCanary struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`      // e.g. "abc123.canary.example.com"
	Severity string `yaml:"severity"`
}

// Sniffer configures the optional Linux AF_PACKET sniffer that watches for
// ARP scans and unsolicited replies.
type Sniffer struct {
	Enabled   bool          `yaml:"enabled"`
	Interface string        `yaml:"interface"`   // empty = all
	ARPScan   ARPScanCfg    `yaml:"arp_scan"`
	Severity  string        `yaml:"severity"`
}

type ARPScanCfg struct {
	DistinctIPs int           `yaml:"distinct_ips"`
	Window      time.Duration `yaml:"window"`
}

type UI struct {
	Enabled      bool   `yaml:"enabled"`
	Bind         string `yaml:"bind"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	AuthTokenEnv string `yaml:"auth_token_env"`
}

type Sensor struct {
	Name         string    `yaml:"name"`
	DataDir      string    `yaml:"data_dir"`
	DeploymentID string    `yaml:"deployment_id"`
	DropUser     string    `yaml:"drop_user"`
	DropGroup    string    `yaml:"drop_group"`
	// Archetype is a deployment-default OS shape (e.g. "debian 12",
	// "Ubuntu 24.04 LTS"). When set, every handler that has an
	// archetype-aware banner (SSH, HTTP, FTP, Telnet, SMTP, MySQL)
	// reports a banner consistent with a stock install of that OS.
	// Per-listener archetype overrides this; per-host honeynet
	// archetype overrides both. Empty = fall back to the v1.0
	// deployment-id-keyed variant pool.
	Archetype    string    `yaml:"archetype"`
	Disk         Disk      `yaml:"disk"`
	Jitter       Jitter    `yaml:"jitter"`
	Shutdown     Shutdown  `yaml:"shutdown"`
	TLSRotate    TLSRotate `yaml:"tls_rotate"`
	GeoIP        GeoIP     `yaml:"geoip"`
	RDNS         RDNS      `yaml:"rdns"`
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
	ID          string        `yaml:"id"`
	Proto       string        `yaml:"proto"`   // tcp | udp
	Bind        string        `yaml:"bind"`    // host:port
	Mode        string        `yaml:"mode"`    // drop | banner | tarpit
	Handler     string        `yaml:"handler"` // raw | ssh | http | https | telnet | ftp | modbus | s7 | iec104 | mqtt
	Banner      string        `yaml:"banner"`
	Severity    string        `yaml:"severity"`
	ReadBytes     int           `yaml:"read_bytes"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	Capture       bool          `yaml:"capture"` // record bidirectional bytes to <data_dir>/captures/<id>.pcap
	MaxConcurrent int           `yaml:"max_concurrent"` // per-listener accept cap; 0 = unlimited (TCP only)
	// Archetype overrides sensor.archetype for this listener. Empty
	// = inherit sensor.archetype. Useful when one sensor serves a
	// mix of OS-shaped traps on different ports.
	Archetype     string        `yaml:"archetype"`
	// AcceptCreds controls which login attempts a credential-capturing
	// handler (ftp_files, ...) treats as a success:
	//   ""/"none"  -> never accept (pure capture; default)
	//   "defaults" -> accept any known vendor-default credential
	//   "any"      -> accept anything (max engagement)
	AcceptCreds   string        `yaml:"accept_creds"`

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
	CN  string `yaml:"cn"`           // certificate Common Name
	Org string `yaml:"org"`          // O= organization
	OU  string `yaml:"ou"`           // OU= organizational unit
	// KeyType selects the key algorithm: "ecdsa" (default, P-256) or
	// "rsa" (2048-bit). Mixing key types across services is a strong
	// "these are different machines" signal to a TLS-fingerprinting
	// scanner.
	KeyType string `yaml:"key_type"`
}

type Tarpit struct {
	Strategy     string        `yaml:"strategy"` // sticky | trickle | keepalive
	MaxPerSource int           `yaml:"max_per_source"`
	MaxTotal     int           `yaml:"max_total"`
	Trickle      TrickleCfg    `yaml:"trickle"`
	Keepalive    KeepaliveCfg  `yaml:"keepalive"`
}

type TrickleCfg struct {
	Text         string        `yaml:"text"`
	ByteInterval time.Duration `yaml:"byte_interval"`
}

type KeepaliveCfg struct {
	Interval time.Duration `yaml:"interval"`
}

type Canary struct {
	ID        string   `yaml:"id"`
	Path      string   `yaml:"path"`
	Recursive bool     `yaml:"recursive"`
	Events    []string `yaml:"events"` // write | remove | rename | create | chmod
	Severity  string   `yaml:"severity"`
}

type Correlate struct {
	PortScan   CorrPortScan   `yaml:"port_scan"`
	BruteForce CorrBruteForce `yaml:"brute_force"`
	SlowScan   CorrSlowScan   `yaml:"slow_scan"`
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
	ID              string        `yaml:"id"`
	Type            string        `yaml:"type"`   // stdout | jsonlog | sqlite | webhook | smtp | syslog | twilio | sns | snmptrap
	Format          string        `yaml:"format"` // json (default) | cef | leef | ocsf
	MinSeverity     string        `yaml:"min_severity"`
	RateLimitPerMin int           `yaml:"rate_limit_per_min"`

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

	// snmptrap
	Community     string `yaml:"community"`
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
	Severity  string `yaml:"severity"`         // ">=low", "<high", "=critical"
	Honeynet  string `yaml:"honeynet"`         // exact match on event.meta.honeynet (the network id)
	HoneynetOS string `yaml:"honeynet_os"`     // exact match on event.meta.honeynet_os
	RuleID    string `yaml:"rule_id"`          // exact match on event.rule_id
}
