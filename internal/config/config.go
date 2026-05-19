package config

import "time"

type Config struct {
	Sensor    Sensor     `yaml:"sensor"`
	Listeners []Listener `yaml:"listeners"`
	Canaries  []Canary   `yaml:"canaries"`
	Correlate Correlate  `yaml:"correlate"`
	Dedup     Dedup      `yaml:"dedup"`
	Allowlist []string   `yaml:"allowlist"`
	Channels  []Channel  `yaml:"channels"`
	Routes    []Route    `yaml:"routes"`
}

type Sensor struct {
	Name    string `yaml:"name"`
	DataDir string `yaml:"data_dir"`
	Disk    Disk   `yaml:"disk"`
}

type Disk struct {
	JSONLogMB int `yaml:"json_log_mb"`
	SQLiteMB  int `yaml:"sqlite_mb"`
	PcapMB    int `yaml:"pcap_mb"`
}

type Listener struct {
	ID          string        `yaml:"id"`
	Proto       string        `yaml:"proto"`   // tcp | udp
	Bind        string        `yaml:"bind"`    // host:port
	Mode        string        `yaml:"mode"`    // drop | banner | tarpit
	Handler     string        `yaml:"handler"` // raw | ssh | http | https | telnet | ftp
	Banner      string        `yaml:"banner"`
	Severity    string        `yaml:"severity"`
	ReadBytes   int           `yaml:"read_bytes"`
	ReadTimeout time.Duration `yaml:"read_timeout"`

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
	Type            string        `yaml:"type"` // stdout | jsonlog | webhook | smtp | syslog
	MinSeverity     string        `yaml:"min_severity"`
	RateLimitPerMin int           `yaml:"rate_limit_per_min"`

	// webhook
	URL           string        `yaml:"url"`
	HMACSecretEnv string        `yaml:"hmac_secret_env"`
	Timeout       time.Duration `yaml:"timeout"`

	// smtp
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
}

type Route struct {
	Match    Match    `yaml:"match"`
	Channels []string `yaml:"channels"`
}

type Match struct {
	Severity string `yaml:"severity"` // ">=low", "<high", "=critical"
}
