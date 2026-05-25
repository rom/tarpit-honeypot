package testharness

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a config time span that unmarshals from either a Go duration
// string ("30m", "3s", "500ms") or a bare number (interpreted as seconds, so a
// natural `duration: 0` works — plain yaml.v3 rejects an int for time.Duration).
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String renders the value like a time.Duration (e.g. for log/error messages).
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML accepts a duration string or a number of seconds. A bare
// number (int or float) is taken as seconds; a string goes through
// time.ParseDuration; null/empty is zero.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!!null":
		*d = 0
		return nil
	case "!!int", "!!float":
		var secs float64
		if err := node.Decode(&secs); err != nil {
			return fmt.Errorf("duration %q: %w", node.Value, err)
		}
		*d = Duration(secs * float64(time.Second))
		return nil
	default:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("duration: want a string like \"30m\" or a number of seconds: %w", err)
		}
		if s == "" {
			*d = 0
			return nil
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
}

// MarshalYAML emits the canonical duration string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config drives the harness. Every field is settable in the YAML config and
// most are overridable on the command line.
type Config struct {
	// Mode selects the backend: "network" (dial the running tool) or "module"
	// (drive a protocol handler in-process, no sensor process).
	Mode string `yaml:"mode"`

	// Host is the network-mode address of an external target (default
	// 127.0.0.1). Ignored for a spawned/managed target (always loopback) and
	// for module mode.
	Host string `yaml:"host"`

	// Spawn, when Binary is set, makes the harness manage the target: it
	// starts the sensor binary with Config, waits for readiness, and can
	// kill+respawn it on a crash. Empty Binary => external/module target.
	Spawn SpawnCfg `yaml:"spawn"`

	// RestartCmd is a shell command run to restart an EXTERNAL target after a
	// crash (e.g. "systemctl restart tarpit-honeypot"). Empty => no restart.
	RestartCmd string `yaml:"restart_cmd"`

	// Endpoints are the services under test (a label + transport + port, or a
	// handler name for module mode).
	Endpoints []Endpoint `yaml:"endpoints"`

	// Rounds is the number of full passes over the selected cases (default 1).
	Rounds int `yaml:"rounds"`
	// Duration is a wall-clock bound; the run stops cleanly when exceeded
	// (0 = run to completion / Rounds). String ("30m") or seconds.
	Duration Duration `yaml:"duration"`
	// Retries is the global per-case retry count on fail/crash (default 1).
	// RetriesByCase overrides it for a specific case id.
	Retries       int            `yaml:"retries"`
	RetriesByCase map[string]int `yaml:"retries_by_case"`
	// Timeout is the per-exchange I/O timeout (default 3s). String ("3s") or seconds.
	Timeout Duration `yaml:"timeout"`
	// Concurrency is how many cases run in parallel (default 1 = deterministic).
	Concurrency int `yaml:"concurrency"`

	// Categories / Cases filter what runs (empty = everything).
	Categories []string `yaml:"categories"`
	Cases      []string `yaml:"cases"`

	// FuzzIterations is the number of inputs per fuzz case (default 64).
	FuzzIterations int `yaml:"fuzz_iterations"`
	// Seed makes fuzzing reproducible/recallable; it is recorded in reports +
	// DB. 0 => DefaultSeed.
	Seed int64 `yaml:"seed"`

	// ScanPorts is the port range scan cases probe (default the endpoint ports
	// plus a small common set). SweepCIDR is the host-sweep range.
	ScanPorts []int  `yaml:"scan_ports"`
	SweepCIDR string `yaml:"sweep_cidr"`

	// Verify points at the target's web API so misimpl/scan/fingerprint cases
	// can confirm the honeypot actually recorded the activity (optional).
	Verify VerifyCfg `yaml:"verify"`

	// Output.
	Quiet    bool        `yaml:"quiet"`
	Progress bool        `yaml:"progress"`
	Reports  []ReportCfg `yaml:"reports"`
	DBPath   string      `yaml:"db"`
}

// Endpoint is one service under test.
type Endpoint struct {
	Label   string `yaml:"label"`   // stable name used in case ids
	Proto   string `yaml:"proto"`   // tcp | udp
	Port    int    `yaml:"port"`    // network mode
	Handler string `yaml:"handler"` // module mode (handler name) / informational
}

// SpawnCfg manages a target sensor process.
type SpawnCfg struct {
	Binary       string   `yaml:"binary"`        // path to the tarpit-honeypot binary
	Config       string   `yaml:"config"`        // -c config passed to `run`
	Args         []string `yaml:"args"`          // extra args
	ReadyTimeout Duration `yaml:"ready_timeout"` // wait this long for ports to open (string or seconds)
	HealthURL    string   `yaml:"health_url"`    // optional readiness probe (e.g. http://127.0.0.1:8088/healthz)
}

// VerifyCfg points the harness at the target's read-only API.
type VerifyCfg struct {
	URL   string `yaml:"url"`   // e.g. http://127.0.0.1:8088
	Token string `yaml:"token"` // auth token if the UI requires one
}

// ReportCfg is one report to write.
type ReportCfg struct {
	Format string `yaml:"format"` // text | json | junit | md | csv | rtf | pdf
	Path   string `yaml:"path"`   // "-" = stdout
}

// DefaultSeed is used when Seed is 0, so a default run is still reproducible.
const DefaultSeed int64 = 0x7a7217

// Load reads + validates a YAML config.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ApplyDefaults()
	return &c, c.Validate()
}

// ApplyDefaults fills zero values.
func (c *Config) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = "network"
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Rounds <= 0 {
		c.Rounds = 1
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.Retries == 0 && c.RetriesByCase == nil {
		c.Retries = 1
	}
	if c.Timeout <= 0 {
		c.Timeout = Duration(3 * time.Second)
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 1
	}
	if c.FuzzIterations <= 0 {
		c.FuzzIterations = 64
	}
	if c.Seed == 0 {
		c.Seed = DefaultSeed
	}
	if c.Spawn.ReadyTimeout <= 0 {
		c.Spawn.ReadyTimeout = Duration(10 * time.Second)
	}
}

// Validate checks the resolved config.
func (c *Config) Validate() error {
	switch c.Mode {
	case "network", "module":
	default:
		return fmt.Errorf("mode %q: must be network or module", c.Mode)
	}
	labels := map[string]bool{}
	for i, e := range c.Endpoints {
		if e.Label == "" {
			return fmt.Errorf("endpoints[%d]: label required", i)
		}
		if labels[e.Label] {
			return fmt.Errorf("endpoint label %q duplicated", e.Label)
		}
		labels[e.Label] = true
		if e.Proto != "tcp" && e.Proto != "udp" {
			return fmt.Errorf("endpoint %q: proto must be tcp or udp", e.Label)
		}
		if c.Mode == "network" && e.Port == 0 {
			return fmt.Errorf("endpoint %q: port required in network mode", e.Label)
		}
		if c.Mode == "module" {
			if e.Handler == "" {
				return fmt.Errorf("endpoint %q: handler required in module mode", e.Label)
			}
			if e.Proto != "tcp" {
				return fmt.Errorf("endpoint %q: module mode supports tcp handlers only", e.Label)
			}
		}
	}
	for _, rep := range c.Reports {
		switch rep.Format {
		case "text", "json", "junit", "md", "csv", "rtf", "pdf":
		default:
			return fmt.Errorf("report format %q: must be text|json|junit|md|csv|rtf|pdf", rep.Format)
		}
	}
	return nil
}

// CaseRetries returns the retry count for a case id (per-case override else
// global).
func (c *Config) CaseRetries(id string) int {
	if n, ok := c.RetriesByCase[id]; ok {
		return n
	}
	return c.Retries
}
