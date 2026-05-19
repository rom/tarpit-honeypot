package config

import "time"

type Config struct {
	Sensor    Sensor          `yaml:"sensor"`
	Listeners []Listener      `yaml:"listeners"`
	Dedup     Dedup           `yaml:"dedup"`
	Allowlist []string        `yaml:"allowlist"`
	Channels  []Channel       `yaml:"channels"`
	Routes    []Route         `yaml:"routes"`
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
	Proto       string        `yaml:"proto"`       // tcp | udp
	Bind        string        `yaml:"bind"`        // host:port
	Mode        string        `yaml:"mode"`        // drop | banner
	Handler     string        `yaml:"handler"`     // raw | (future: ssh,http,...)
	Banner      string        `yaml:"banner"`
	Severity    string        `yaml:"severity"`
	ReadBytes   int           `yaml:"read_bytes"`
	ReadTimeout time.Duration `yaml:"read_timeout"`
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
