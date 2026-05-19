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
	Dedup        Dedup        `yaml:"dedup"`
	Allowlist    []string     `yaml:"allowlist"`
	Channels     []Channel    `yaml:"channels"`
	Routes       []Route      `yaml:"routes"`
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
	Name         string `yaml:"name"`
	DataDir      string `yaml:"data_dir"`
	DeploymentID string `yaml:"deployment_id"`
	DropUser     string `yaml:"drop_user"`
	DropGroup    string `yaml:"drop_group"`
	Disk         Disk   `yaml:"disk"`
	Jitter       Jitter `yaml:"jitter"`
	Shutdown     Shutdown `yaml:"shutdown"`
	TLSRotate    TLSRotate `yaml:"tls_rotate"`
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

	HTTPS  HTTPS  `yaml:"https"`
	Tarpit Tarpit `yaml:"tarpit"`
}

type HTTPS struct {
	Hosts []string `yaml:"hosts"`
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
	Type            string        `yaml:"type"` // stdout | jsonlog | sqlite | webhook | smtp | syslog | twilio | sns | snmptrap
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
}

type Route struct {
	Match    Match    `yaml:"match"`
	Channels []string `yaml:"channels"`
}

type Match struct {
	Severity string `yaml:"severity"` // ">=low", "<high", "=critical"
}
