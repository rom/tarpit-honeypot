package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/event"
	"gopkg.in/yaml.v3"
)

// tcpHandlers / udpHandlers are the per-protocol handler whitelists used
// by Validate and surfaced (sorted) by TCPHandlerNames / UDPHandlerNames
// so the `tarpit-honeypot list-handlers` command stays in lock-step with
// what the validator actually accepts.
var tcpHandlers = map[string]bool{
	"raw": true, "ssh": true, "ssh_interactive": true,
	"http": true, "https": true,
	"telnet": true, "ftp": true, "ftp_files": true,
	"modbus": true, "s7": true, "iec104": true, "mqtt": true,
	"s7comm_plus": true, "dnp3": true, "ge_srtp": true, "codesys": true,
	"rsync": true, "gopher": true, "socks": true, "bgp": true,
	"atg": true, "fox": true, "hartip": true, "pcworx": true, "mms": true,
	"pjl": true, "lpd": true, "ads": true,
	"opcua": true, "ethernetip": true, "smb": true,
	"vnc": true, "smtp_recv": true, "rdp": true, "winrm": true,
	"dcerpc": true, "ldap": true, "kerberos": true,
	"postgres": true, "mysql": true, "redis": true,
	"memcached": true, "pop3": true, "imap": true,
	"mongodb": true, "elasticsearch": true,
	// implicit-TLS variants (993/995/465/636/8883/990): the plaintext handler
	// run over a TLS handshake (see handler.tlsWrap).
	"smtps": true, "imaps": true, "pop3s": true,
	"ldaps": true, "mqtts": true, "ftps": true,
	"syslog_tcp": true, "rtsp": true, "dockerapi": true, "melsec": true,
	"cloud_metadata": true, "etcd": true,
	"websocket": true, "grpc": true, "ssrf_canary": true,
	"kubernetes_api": true, "vault": true,
	"jdwp": true, "rmi": true, "git": true, "zookeeper": true, "kafka": true,
	"cassandra": true, "nats": true, "rpcbind": true, "pptp": true,
	"adb": true, "ajp13": true, "epmd": true, "tacacs": true,
	"fins_tcp": true, "secs_gem": true, "pcom": true,
	"rexec": true, "rsh": true, "pcanywhere": true, "radmin": true,
	"dameware": true, "pcoip": true, "spice": true, "lantronix": true,
	"tn3270": true, "ard": true,
	"sip_tcp": true, "sccp": true, "h323": true, "asterisk_ami": true,
	"xmpp": true, "amqp": true, "ipp": true,
	"mssql": true, "oracle_tns": true,
	"teamviewer": true, "anydesk": true, "openvpn": true, "citrix_ica": true,
	"vmware_authd": true, "x11": true, "rlogin": true, "nx": true, "redfish": true,
	"intel_amt": true, "ilo": true, "idrac": true, "esxi": true,
	"fortinet": true, "pulse": true, "citrix_gateway": true,
	"horizon": true, "moxa_mgmt": true,
	"echo": true, "discard": true, "daytime": true,
	"qotd": true, "chargen": true, "time": true,
	"lua": true, "scripted": true, "auto": true,
	"tls_intercept": true,
}

var udpHandlers = map[string]bool{
	"raw": true, "snmp": true, "ntp": true,
	"bacnet": true, "tftp": true, "ipmi": true,
	"syslog_udp": true, "radius": true, "sip": true,
	"ssdp": true, "cldap": true, "llmnr": true, "nbns": true,
	"mdns": true,
	"dns":  true,
	"echo": true, "discard": true, "daytime": true,
	"qotd": true, "chargen": true, "time": true,
	"fins": true,
	"coap": true, "knx": true, "dhcp": true,
	"isakmp": true, "netbios_dgram": true, "stun": true,
	"mssql_browser": true, "profinet": true, "wdbrpc": true, "iax2": true,
	"dtls": true, "quic": true,
	"netflow": true, "sflow": true,
	"auto": true,
}

// TCPHandlerNames returns the sorted set of handler names accepted on a
// tcp listener. UDPHandlerNames is the udp equivalent.
func TCPHandlerNames() []string { return sortedKeys(tcpHandlers) }

// UDPHandlerNames returns the sorted set of handler names accepted on a
// udp listener.
func UDPHandlerNames() []string { return sortedKeys(udpHandlers) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadDefaultsOnly returns a Config populated with applyDefaults but
// without running Validate — used by `tarpit-honeypot init` to scaffold
// a config skeleton (the empty document would fail listener/channel
// validation otherwise).
func LoadDefaultsOnly(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	// Expand archeservice role bundles into listeners first, so the
	// generated listeners pick up the per-listener defaults below.
	c.expandArcheservices()
	c.Interaction.ApplyDefaults()
	if c.Sensor.DataDir == "" {
		c.Sensor.DataDir = "/var/lib/tarpit-honeypot"
	}
	if c.Sensor.Disk.JSONLogMB == 0 {
		c.Sensor.Disk.JSONLogMB = 500
	}
	if c.Sensor.Disk.SQLiteMB == 0 {
		c.Sensor.Disk.SQLiteMB = 500
	}
	if c.Sensor.Disk.PcapMB == 0 {
		c.Sensor.Disk.PcapMB = 1024
	}
	if c.Sensor.Disk.CaptureKB == 0 {
		c.Sensor.Disk.CaptureKB = 64
	}
	if c.Sensor.Shutdown.DrainTimeout == 0 {
		c.Sensor.Shutdown.DrainTimeout = 10 * time.Second
	}
	if c.Sensor.Jitter.Enabled && c.Sensor.Jitter.MaxMS == 0 {
		c.Sensor.Jitter.MaxMS = 50
	}
	if c.Sensor.Jitter.Enabled && c.Sensor.Jitter.MinMS == 0 {
		c.Sensor.Jitter.MinMS = 5
	}
	if c.Dedup.DefaultWindow == 0 {
		c.Dedup.DefaultWindow = 5 * time.Minute
	}
	// DNS amplifier-detection defaults (the dnscanary server parses these at
	// startup, so they must be complete by run time, not just validate time).
	if c.DNS.AmplifierDetection.Enabled {
		if c.DNS.AmplifierDetection.Severity == "" {
			c.DNS.AmplifierDetection.Severity = "high"
		}
		if c.DNS.AmplifierDetection.Window == 0 {
			c.DNS.AmplifierDetection.Window = 10 * time.Second
		}
		if c.DNS.AmplifierDetection.Queries == 0 {
			c.DNS.AmplifierDetection.Queries = 50
		}
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Mode == "" {
			l.Mode = "drop"
		}
		if l.Handler == "" {
			l.Handler = "raw"
		}
		if l.Severity == "" {
			l.Severity = "medium"
		}
		if l.ReadBytes == 0 {
			l.ReadBytes = 1024
		}
		if l.ReadTimeout == 0 {
			l.ReadTimeout = 5 * time.Second
		}
		if l.Mode == "tarpit" {
			t := &l.Tarpit
			if t.Strategy == "" {
				t.Strategy = "sticky"
			}
			if t.MaxPerSource == 0 {
				t.MaxPerSource = 4
			}
			if t.MaxTotal == 0 {
				t.MaxTotal = 256
			}
			if t.Trickle.ByteInterval == 0 {
				t.Trickle.ByteInterval = 2 * time.Second
			}
			if t.Keepalive.Interval == 0 {
				t.Keepalive.Interval = 30 * time.Second
			}
			if t.Jitter.MinInterval == 0 {
				t.Jitter.MinInterval = 500 * time.Millisecond
			}
			if t.Jitter.MaxInterval == 0 {
				t.Jitter.MaxInterval = 5 * time.Second
			}
			if t.Backoff.Start == 0 {
				t.Backoff.Start = 500 * time.Millisecond
			}
			if t.Backoff.Max == 0 {
				t.Backoff.Max = 60 * time.Second
			}
			if t.Backoff.Factor == 0 {
				t.Backoff.Factor = 2
			}
			if t.SSHBanner.LineInterval == 0 {
				t.SSHBanner.LineInterval = 2 * time.Second
			}
			if t.SSHBanner.MaxLineBytes == 0 {
				t.SSHBanner.MaxLineBytes = 32
			}
			if t.HTTP.HeaderInterval == 0 {
				t.HTTP.HeaderInterval = 2 * time.Second
			}
			if t.HTTP.ChunkInterval == 0 {
				t.HTTP.ChunkInterval = 2 * time.Second
			}
			if t.Echo.ByteInterval == 0 {
				t.Echo.ByteInterval = 1 * time.Second
			}
			if t.Babble.ByteInterval == 0 {
				t.Babble.ByteInterval = 2 * time.Second
			}
			if t.ZipBomb.DecompressedSize == 0 {
				t.ZipBomb.DecompressedSize = 10 << 30 // 10 GiB inflated
			}
			if t.ZeroWindow.ReadBuffer == 0 {
				t.ZeroWindow.ReadBuffer = 1
			}
		}
	}
	for i := range c.Canaries {
		ca := &c.Canaries[i]
		if ca.Severity == "" {
			ca.Severity = "critical"
		}
		if len(ca.Events) == 0 {
			ca.Events = []string{"write", "remove", "rename"}
		}
	}
	for i := range c.URLCanaries {
		uc := &c.URLCanaries[i]
		if uc.Severity == "" {
			uc.Severity = "critical"
		}
	}
	for i := range c.DNSCanaries {
		dc := &c.DNSCanaries[i]
		if dc.Severity == "" {
			dc.Severity = "critical"
		}
		dc.Name = strings.ToLower(strings.TrimSuffix(dc.Name, "."))
	}
	if c.Sniffer.Enabled {
		if c.Sniffer.Severity == "" {
			c.Sniffer.Severity = "high"
		}
		if c.Sniffer.ARPScan.DistinctIPs == 0 {
			c.Sniffer.ARPScan.DistinctIPs = 16
		}
		if c.Sniffer.ARPScan.Window == 0 {
			c.Sniffer.ARPScan.Window = 30 * time.Second
		}
		if c.Sniffer.TCPScan.Enabled {
			if c.Sniffer.TCPScan.DistinctPorts == 0 {
				c.Sniffer.TCPScan.DistinctPorts = 16
			}
			if c.Sniffer.TCPScan.StealthPorts == 0 {
				c.Sniffer.TCPScan.StealthPorts = 3
			}
			if c.Sniffer.TCPScan.Window == 0 {
				c.Sniffer.TCPScan.Window = 30 * time.Second
			}
		}
	}
	if c.Correlate.PortScan.Enabled {
		if c.Correlate.PortScan.DistinctPorts == 0 {
			c.Correlate.PortScan.DistinctPorts = 5
		}
		if c.Correlate.PortScan.Window == 0 {
			c.Correlate.PortScan.Window = 30 * time.Second
		}
		if c.Correlate.PortScan.Severity == "" {
			c.Correlate.PortScan.Severity = "high"
		}
	}
	if c.Correlate.BruteForce.Enabled {
		if c.Correlate.BruteForce.Attempts == 0 {
			c.Correlate.BruteForce.Attempts = 10
		}
		if c.Correlate.BruteForce.Window == 0 {
			c.Correlate.BruteForce.Window = 60 * time.Second
		}
		if c.Correlate.BruteForce.Severity == "" {
			c.Correlate.BruteForce.Severity = "high"
		}
	}
	if c.Correlate.SlowScan.Enabled {
		if c.Correlate.SlowScan.DistinctPorts == 0 {
			c.Correlate.SlowScan.DistinctPorts = 10
		}
		if c.Correlate.SlowScan.Window == 0 {
			c.Correlate.SlowScan.Window = 24 * time.Hour
		}
		if c.Correlate.SlowScan.Severity == "" {
			c.Correlate.SlowScan.Severity = "high"
		}
	}
	if c.Correlate.PasswordSpray.Enabled {
		if c.Correlate.PasswordSpray.DistinctUsers == 0 {
			c.Correlate.PasswordSpray.DistinctUsers = 5
		}
		if c.Correlate.PasswordSpray.Window == 0 {
			c.Correlate.PasswordSpray.Window = 300 * time.Second
		}
		if c.Correlate.PasswordSpray.Severity == "" {
			c.Correlate.PasswordSpray.Severity = "high"
		}
	}
	if c.Correlate.CredReuse.Enabled {
		if c.Correlate.CredReuse.DistinctSources == 0 {
			c.Correlate.CredReuse.DistinctSources = 3
		}
		if c.Correlate.CredReuse.Window == 0 {
			c.Correlate.CredReuse.Window = time.Hour
		}
		if c.Correlate.CredReuse.Severity == "" {
			c.Correlate.CredReuse.Severity = "high"
		}
	}
	if c.Correlate.ICMPSweep.Enabled {
		if c.Correlate.ICMPSweep.DistinctIPs == 0 {
			c.Correlate.ICMPSweep.DistinctIPs = 10
		}
		if c.Correlate.ICMPSweep.Window == 0 {
			c.Correlate.ICMPSweep.Window = 60 * time.Second
		}
		if c.Correlate.ICMPSweep.Severity == "" {
			c.Correlate.ICMPSweep.Severity = "medium"
		}
	}
	if c.Correlate.PathEnum.Enabled {
		if c.Correlate.PathEnum.DistinctPaths == 0 {
			c.Correlate.PathEnum.DistinctPaths = 50
		}
		if c.Correlate.PathEnum.Window == 0 {
			c.Correlate.PathEnum.Window = 60 * time.Second
		}
		if c.Correlate.PathEnum.Severity == "" {
			c.Correlate.PathEnum.Severity = "high"
		}
	}
	if c.Correlate.DNSEnum.Enabled {
		if c.Correlate.DNSEnum.DistinctNames == 0 {
			c.Correlate.DNSEnum.DistinctNames = 50
		}
		if c.Correlate.DNSEnum.Window == 0 {
			c.Correlate.DNSEnum.Window = 60 * time.Second
		}
		if c.Correlate.DNSEnum.Severity == "" {
			c.Correlate.DNSEnum.Severity = "medium"
		}
	}
	if c.Correlate.Beacon.Enabled {
		if c.Correlate.Beacon.MinHits == 0 {
			c.Correlate.Beacon.MinHits = 6
		}
		if c.Correlate.Beacon.MaxJitterPct == 0 {
			c.Correlate.Beacon.MaxJitterPct = 20
		}
		if c.Correlate.Beacon.Window == 0 {
			c.Correlate.Beacon.Window = time.Hour
		}
		if c.Correlate.Beacon.Severity == "" {
			c.Correlate.Beacon.Severity = "high"
		}
	}
	if c.Correlate.HostSweep.Enabled {
		if c.Correlate.HostSweep.DistinctHosts == 0 {
			c.Correlate.HostSweep.DistinctHosts = 10
		}
		if c.Correlate.HostSweep.Window == 0 {
			c.Correlate.HostSweep.Window = 60 * time.Second
		}
		if c.Correlate.HostSweep.Severity == "" {
			c.Correlate.HostSweep.Severity = "high"
		}
	}
	if c.Correlate.ServiceSweep.Enabled {
		if c.Correlate.ServiceSweep.DistinctServices == 0 {
			c.Correlate.ServiceSweep.DistinctServices = 5
		}
		if c.Correlate.ServiceSweep.Window == 0 {
			c.Correlate.ServiceSweep.Window = 60 * time.Second
		}
		if c.Correlate.ServiceSweep.Severity == "" {
			c.Correlate.ServiceSweep.Severity = "medium"
		}
	}
	if c.Correlate.UARotation.Enabled {
		if c.Correlate.UARotation.DistinctAgents == 0 {
			c.Correlate.UARotation.DistinctAgents = 4
		}
		if c.Correlate.UARotation.Window == 0 {
			c.Correlate.UARotation.Window = 300 * time.Second
		}
		if c.Correlate.UARotation.Severity == "" {
			c.Correlate.UARotation.Severity = "medium"
		}
	}
	if c.Correlate.ExploitChain.Enabled {
		if c.Correlate.ExploitChain.DistinctCVEs == 0 {
			c.Correlate.ExploitChain.DistinctCVEs = 2
		}
		if c.Correlate.ExploitChain.Window == 0 {
			c.Correlate.ExploitChain.Window = 600 * time.Second
		}
		if c.Correlate.ExploitChain.Severity == "" {
			c.Correlate.ExploitChain.Severity = "critical"
		}
	}
	if c.Correlate.ICSControl.Enabled {
		if c.Correlate.ICSControl.Attempts == 0 {
			c.Correlate.ICSControl.Attempts = 3
		}
		if c.Correlate.ICSControl.Window == 0 {
			c.Correlate.ICSControl.Window = 300 * time.Second
		}
		if c.Correlate.ICSControl.Severity == "" {
			c.Correlate.ICSControl.Severity = "critical"
		}
	}
	if c.Correlate.CanaryTrip.Enabled {
		if c.Correlate.CanaryTrip.DistinctTokens == 0 {
			c.Correlate.CanaryTrip.DistinctTokens = 2
		}
		if c.Correlate.CanaryTrip.Window == 0 {
			c.Correlate.CanaryTrip.Window = time.Hour
		}
		if c.Correlate.CanaryTrip.Severity == "" {
			c.Correlate.CanaryTrip.Severity = "critical"
		}
	}
	if c.Correlate.FingerprintReuse.Enabled {
		if c.Correlate.FingerprintReuse.DistinctSources == 0 {
			c.Correlate.FingerprintReuse.DistinctSources = 5
		}
		if c.Correlate.FingerprintReuse.Window == 0 {
			c.Correlate.FingerprintReuse.Window = time.Hour
		}
		if c.Correlate.FingerprintReuse.Severity == "" {
			c.Correlate.FingerprintReuse.Severity = "medium"
		}
	}
	if c.Correlate.ProtocolViolation.Enabled {
		if c.Correlate.ProtocolViolation.DistinctAnomalies == 0 {
			c.Correlate.ProtocolViolation.DistinctAnomalies = 5
		}
		if c.Correlate.ProtocolViolation.Window == 0 {
			c.Correlate.ProtocolViolation.Window = 300 * time.Second
		}
		if c.Correlate.ProtocolViolation.Severity == "" {
			c.Correlate.ProtocolViolation.Severity = "medium"
		}
	}
	if c.Correlate.Exfil.Enabled {
		if c.Correlate.Exfil.Bytes == 0 {
			c.Correlate.Exfil.Bytes = 1 << 20 // 1 MiB
		}
		if c.Correlate.Exfil.Window == 0 {
			c.Correlate.Exfil.Window = 300 * time.Second
		}
		if c.Correlate.Exfil.Severity == "" {
			c.Correlate.Exfil.Severity = "high"
		}
	}
	if c.Correlate.SessionFlood.Enabled {
		if c.Correlate.SessionFlood.Connections == 0 {
			c.Correlate.SessionFlood.Connections = 200
		}
		if c.Correlate.SessionFlood.Window == 0 {
			c.Correlate.SessionFlood.Window = 60 * time.Second
		}
		if c.Correlate.SessionFlood.Severity == "" {
			c.Correlate.SessionFlood.Severity = "medium"
		}
	}
	if c.Correlate.LateralMovement.Enabled {
		if c.Correlate.LateralMovement.DistinctServices == 0 {
			c.Correlate.LateralMovement.DistinctServices = 3
		}
		if c.Correlate.LateralMovement.Window == 0 {
			c.Correlate.LateralMovement.Window = 300 * time.Second
		}
		if c.Correlate.LateralMovement.Severity == "" {
			c.Correlate.LateralMovement.Severity = "high"
		}
	}
	if c.Correlate.OTRecon.Enabled {
		if c.Correlate.OTRecon.DistinctServices == 0 {
			c.Correlate.OTRecon.DistinctServices = 3
		}
		if c.Correlate.OTRecon.Window == 0 {
			c.Correlate.OTRecon.Window = 300 * time.Second
		}
		if c.Correlate.OTRecon.Severity == "" {
			c.Correlate.OTRecon.Severity = "high"
		}
	}
	if c.Correlate.DataAccess.Enabled {
		if c.Correlate.DataAccess.Attempts == 0 {
			c.Correlate.DataAccess.Attempts = 5
		}
		if c.Correlate.DataAccess.Window == 0 {
			c.Correlate.DataAccess.Window = 300 * time.Second
		}
		if c.Correlate.DataAccess.Severity == "" {
			c.Correlate.DataAccess.Severity = "high"
		}
	}
	if c.Correlate.MalwareCampaign.Enabled {
		if c.Correlate.MalwareCampaign.Captures == 0 {
			c.Correlate.MalwareCampaign.Captures = 2
		}
		if c.Correlate.MalwareCampaign.Window == 0 {
			c.Correlate.MalwareCampaign.Window = 600 * time.Second
		}
		if c.Correlate.MalwareCampaign.Severity == "" {
			c.Correlate.MalwareCampaign.Severity = "critical"
		}
	}
	if c.Correlate.Webshell.Enabled {
		if c.Correlate.Webshell.Attempts == 0 {
			c.Correlate.Webshell.Attempts = 2
		}
		if c.Correlate.Webshell.Window == 0 {
			c.Correlate.Webshell.Window = 600 * time.Second
		}
		if c.Correlate.Webshell.Severity == "" {
			c.Correlate.Webshell.Severity = "critical"
		}
	}
	if c.Correlate.ThreatIntelBurst.Enabled {
		if c.Correlate.ThreatIntelBurst.Events == 0 {
			c.Correlate.ThreatIntelBurst.Events = 4
		}
		if c.Correlate.ThreatIntelBurst.Window == 0 {
			c.Correlate.ThreatIntelBurst.Window = 10 * time.Minute
		}
		if c.Correlate.ThreatIntelBurst.Severity == "" {
			c.Correlate.ThreatIntelBurst.Severity = "high"
		}
	}
	if c.Correlate.GeoVelocity.Enabled {
		if c.Correlate.GeoVelocity.DistinctCountries == 0 {
			c.Correlate.GeoVelocity.DistinctCountries = 2
		}
		if c.Correlate.GeoVelocity.Window == 0 {
			c.Correlate.GeoVelocity.Window = time.Hour
		}
		if c.Correlate.GeoVelocity.Severity == "" {
			c.Correlate.GeoVelocity.Severity = "high"
		}
	}
	if c.Correlate.AmplificationProbe.Enabled {
		if c.Correlate.AmplificationProbe.DistinctServices == 0 {
			c.Correlate.AmplificationProbe.DistinctServices = 3
		}
		if c.Correlate.AmplificationProbe.Window == 0 {
			c.Correlate.AmplificationProbe.Window = 5 * time.Minute
		}
		if c.Correlate.AmplificationProbe.Severity == "" {
			c.Correlate.AmplificationProbe.Severity = "high"
		}
	}
	if c.Correlate.DefaultCredSweep.Enabled {
		if c.Correlate.DefaultCredSweep.DistinctServices == 0 {
			c.Correlate.DefaultCredSweep.DistinctServices = 3
		}
		if c.Correlate.DefaultCredSweep.Window == 0 {
			c.Correlate.DefaultCredSweep.Window = 5 * time.Minute
		}
		if c.Correlate.DefaultCredSweep.Severity == "" {
			c.Correlate.DefaultCredSweep.Severity = "high"
		}
	}
	if c.Correlate.CVECampaign.Enabled {
		if c.Correlate.CVECampaign.DistinctSources == 0 {
			c.Correlate.CVECampaign.DistinctSources = 3
		}
		if c.Correlate.CVECampaign.Window == 0 {
			c.Correlate.CVECampaign.Window = time.Hour
		}
		if c.Correlate.CVECampaign.Severity == "" {
			c.Correlate.CVECampaign.Severity = "critical"
		}
	}
	if c.Correlate.DestructiveAction.Enabled {
		if c.Correlate.DestructiveAction.Events == 0 {
			c.Correlate.DestructiveAction.Events = 2
		}
		if c.Correlate.DestructiveAction.Window == 0 {
			c.Correlate.DestructiveAction.Window = 10 * time.Minute
		}
		if c.Correlate.DestructiveAction.Severity == "" {
			c.Correlate.DestructiveAction.Severity = "critical"
		}
	}
	if c.Correlate.CloudCredTheft.Enabled {
		if c.Correlate.CloudCredTheft.Events == 0 {
			c.Correlate.CloudCredTheft.Events = 2
		}
		if c.Correlate.CloudCredTheft.Window == 0 {
			c.Correlate.CloudCredTheft.Window = 10 * time.Minute
		}
		if c.Correlate.CloudCredTheft.Severity == "" {
			c.Correlate.CloudCredTheft.Severity = "critical"
		}
	}
	if c.Correlate.SSRFCallback.Enabled {
		if c.Correlate.SSRFCallback.Events == 0 {
			c.Correlate.SSRFCallback.Events = 3
		}
		if c.Correlate.SSRFCallback.Window == 0 {
			c.Correlate.SSRFCallback.Window = 10 * time.Minute
		}
		if c.Correlate.SSRFCallback.Severity == "" {
			c.Correlate.SSRFCallback.Severity = "high"
		}
	}
	if c.Correlate.TLSMITMCapture.Enabled {
		if c.Correlate.TLSMITMCapture.Events == 0 {
			c.Correlate.TLSMITMCapture.Events = 2
		}
		if c.Correlate.TLSMITMCapture.Window == 0 {
			c.Correlate.TLSMITMCapture.Window = 10 * time.Minute
		}
		if c.Correlate.TLSMITMCapture.Severity == "" {
			c.Correlate.TLSMITMCapture.Severity = "critical"
		}
	}
	if c.Correlate.FingerprintRotation.Enabled {
		if c.Correlate.FingerprintRotation.DistinctFingerprints == 0 {
			c.Correlate.FingerprintRotation.DistinctFingerprints = 4
		}
		if c.Correlate.FingerprintRotation.Window == 0 {
			c.Correlate.FingerprintRotation.Window = 10 * time.Minute
		}
		if c.Correlate.FingerprintRotation.Severity == "" {
			c.Correlate.FingerprintRotation.Severity = "medium"
		}
	}
	if c.Correlate.ContainerTakeover.Enabled {
		if c.Correlate.ContainerTakeover.DistinctOps == 0 {
			c.Correlate.ContainerTakeover.DistinctOps = 2
		}
		if c.Correlate.ContainerTakeover.Window == 0 {
			c.Correlate.ContainerTakeover.Window = 10 * time.Minute
		}
		if c.Correlate.ContainerTakeover.Severity == "" {
			c.Correlate.ContainerTakeover.Severity = "critical"
		}
	}
	if c.Correlate.WebAttackProbe.Enabled {
		if c.Correlate.WebAttackProbe.DistinctClasses == 0 {
			c.Correlate.WebAttackProbe.DistinctClasses = 3
		}
		if c.Correlate.WebAttackProbe.Window == 0 {
			c.Correlate.WebAttackProbe.Window = 10 * time.Minute
		}
		if c.Correlate.WebAttackProbe.Severity == "" {
			c.Correlate.WebAttackProbe.Severity = "high"
		}
	}
	if c.Correlate.SSHKeySpray.Enabled {
		if c.Correlate.SSHKeySpray.DistinctKeys == 0 {
			c.Correlate.SSHKeySpray.DistinctKeys = 5
		}
		if c.Correlate.SSHKeySpray.Window == 0 {
			c.Correlate.SSHKeySpray.Window = 10 * time.Minute
		}
		if c.Correlate.SSHKeySpray.Severity == "" {
			c.Correlate.SSHKeySpray.Severity = "medium"
		}
	}
	if c.Correlate.SpamRelay.Enabled {
		if c.Correlate.SpamRelay.Events == 0 {
			c.Correlate.SpamRelay.Events = 3
		}
		if c.Correlate.SpamRelay.Window == 0 {
			c.Correlate.SpamRelay.Window = 10 * time.Minute
		}
		if c.Correlate.SpamRelay.Severity == "" {
			c.Correlate.SpamRelay.Severity = "medium"
		}
	}
	if c.Correlate.DNSTunnel.Enabled {
		if c.Correlate.DNSTunnel.Events == 0 {
			c.Correlate.DNSTunnel.Events = 5
		}
		if c.Correlate.DNSTunnel.Window == 0 {
			c.Correlate.DNSTunnel.Window = 10 * time.Minute
		}
		if c.Correlate.DNSTunnel.Severity == "" {
			c.Correlate.DNSTunnel.Severity = "high"
		}
	}
	if c.Correlate.ReconToExploit.Enabled {
		if c.Correlate.ReconToExploit.Window == 0 {
			c.Correlate.ReconToExploit.Window = 30 * time.Minute
		}
		if c.Correlate.ReconToExploit.Severity == "" {
			c.Correlate.ReconToExploit.Severity = "high"
		}
	}
	if c.Correlate.HoneytokenSpread.Enabled {
		if c.Correlate.HoneytokenSpread.DistinctSources == 0 {
			c.Correlate.HoneytokenSpread.DistinctSources = 3
		}
		if c.Correlate.HoneytokenSpread.Window == 0 {
			c.Correlate.HoneytokenSpread.Window = time.Hour
		}
		if c.Correlate.HoneytokenSpread.Severity == "" {
			c.Correlate.HoneytokenSpread.Severity = "high"
		}
	}
	if c.Correlate.ToolRotation.Enabled {
		if c.Correlate.ToolRotation.DistinctTools == 0 {
			c.Correlate.ToolRotation.DistinctTools = 3
		}
		if c.Correlate.ToolRotation.Window == 0 {
			c.Correlate.ToolRotation.Window = time.Hour
		}
		if c.Correlate.ToolRotation.Severity == "" {
			c.Correlate.ToolRotation.Severity = "high"
		}
	}
	if c.Correlate.PLCProgramDownload.Enabled {
		if c.Correlate.PLCProgramDownload.Events == 0 {
			c.Correlate.PLCProgramDownload.Events = 1
		}
		if c.Correlate.PLCProgramDownload.Window == 0 {
			c.Correlate.PLCProgramDownload.Window = 10 * time.Minute
		}
		if c.Correlate.PLCProgramDownload.Severity == "" {
			c.Correlate.PLCProgramDownload.Severity = "critical"
		}
	}
	if c.Correlate.ICSModeChange.Enabled {
		if c.Correlate.ICSModeChange.Events == 0 {
			c.Correlate.ICSModeChange.Events = 1
		}
		if c.Correlate.ICSModeChange.Window == 0 {
			c.Correlate.ICSModeChange.Window = 10 * time.Minute
		}
		if c.Correlate.ICSModeChange.Severity == "" {
			c.Correlate.ICSModeChange.Severity = "critical"
		}
	}
	if c.Correlate.OTKillChain.Enabled {
		if c.Correlate.OTKillChain.Window == 0 {
			c.Correlate.OTKillChain.Window = 10 * time.Minute
		}
		if c.Correlate.OTKillChain.Severity == "" {
			c.Correlate.OTKillChain.Severity = "critical"
		}
	}
	if c.Correlate.RemoteToolSweep.Enabled {
		if c.Correlate.RemoteToolSweep.DistinctTools == 0 {
			c.Correlate.RemoteToolSweep.DistinctTools = 3
		}
		if c.Correlate.RemoteToolSweep.Window == 0 {
			c.Correlate.RemoteToolSweep.Window = 5 * time.Minute
		}
		if c.Correlate.RemoteToolSweep.Severity == "" {
			c.Correlate.RemoteToolSweep.Severity = "high"
		}
	}
	if c.Correlate.OOBMgmtAccess.Enabled {
		if c.Correlate.OOBMgmtAccess.DistinctServices == 0 {
			c.Correlate.OOBMgmtAccess.DistinctServices = 3
		}
		if c.Correlate.OOBMgmtAccess.Window == 0 {
			c.Correlate.OOBMgmtAccess.Window = 5 * time.Minute
		}
		if c.Correlate.OOBMgmtAccess.Severity == "" {
			c.Correlate.OOBMgmtAccess.Severity = "high"
		}
	}
	if c.Correlate.RemoteExecCommand.Enabled {
		if c.Correlate.RemoteExecCommand.Events == 0 {
			c.Correlate.RemoteExecCommand.Events = 1
		}
		if c.Correlate.RemoteExecCommand.Window == 0 {
			c.Correlate.RemoteExecCommand.Window = 10 * time.Minute
		}
		if c.Correlate.RemoteExecCommand.Severity == "" {
			c.Correlate.RemoteExecCommand.Severity = "critical"
		}
	}
	if c.Correlate.TollFraud.Enabled {
		if c.Correlate.TollFraud.Events == 0 {
			c.Correlate.TollFraud.Events = 5
		}
		if c.Correlate.TollFraud.Window == 0 {
			c.Correlate.TollFraud.Window = 5 * time.Minute
		}
		if c.Correlate.TollFraud.Severity == "" {
			c.Correlate.TollFraud.Severity = "high"
		}
	}
	if c.Correlate.VoIPEnum.Enabled {
		if c.Correlate.VoIPEnum.DistinctServices == 0 {
			c.Correlate.VoIPEnum.DistinctServices = 3
		}
		if c.Correlate.VoIPEnum.Window == 0 {
			c.Correlate.VoIPEnum.Window = 5 * time.Minute
		}
		if c.Correlate.VoIPEnum.Severity == "" {
			c.Correlate.VoIPEnum.Severity = "high"
		}
	}
	if c.Correlate.PBXControl.Enabled {
		if c.Correlate.PBXControl.Events == 0 {
			c.Correlate.PBXControl.Events = 3
		}
		if c.Correlate.PBXControl.Window == 0 {
			c.Correlate.PBXControl.Window = 10 * time.Minute
		}
		if c.Correlate.PBXControl.Severity == "" {
			c.Correlate.PBXControl.Severity = "high"
		}
	}
	for i := range c.Channels {
		ch := &c.Channels[i]
		if ch.MinSeverity == "" {
			ch.MinSeverity = "low"
		}
		if (ch.Type == "webhook" || ch.Type == "discord") && ch.Timeout == 0 {
			ch.Timeout = 5 * time.Second
		}
		if ch.Type == "syslog" && ch.Network == "" {
			ch.Network = "local"
		}
		if ch.Type == "syslog" && ch.Tag == "" {
			ch.Tag = "tarpit-honeypot"
		}
	}

	// Active-response blocklist defaults (only meaningful when enabled).
	if c.Risk.Block.Enabled {
		if c.Risk.Block.Level == "" {
			c.Risk.Block.Level = "critical"
		}
		if c.Risk.Block.TTL == 0 {
			c.Risk.Block.TTL = 15 * time.Minute
		}
		if c.Risk.Block.Table == "" {
			c.Risk.Block.Table = "tarpit_blocklist"
		}
	}
}

func (c *Config) Validate() error {
	// Sensor archetype: rejected at parse time so typos in the
	// deployment-default surface immediately rather than producing
	// the silent fall-back to the identity-based banner pool.
	if c.Sensor.Archetype != "" && archetype.Lookup(c.Sensor.Archetype) == nil {
		return fmt.Errorf("sensor.archetype %q is not a known archetype; run `tarpit-honeypot help archetypes` for the list", c.Sensor.Archetype)
	}

	// Interaction depth + experimental-feature guardrails.
	if err := c.Interaction.validate(); err != nil {
		return err
	}

	// Severity overrides: rule non-empty, severity parseable. Compiling here
	// surfaces a typo at load/validate time rather than first dispatch.
	if _, err := CompileSeverityOverrides(c.SeverityOverrides); err != nil {
		return err
	}

	// Forward targets: id + url required, ids unique, min_severity parseable.
	seenFwd := map[string]bool{}
	for _, f := range c.Forward {
		if f.ID == "" || f.URL == "" {
			return fmt.Errorf("forward target: id and url are required")
		}
		if seenFwd[f.ID] {
			return fmt.Errorf("forward target %q: duplicate id", f.ID)
		}
		seenFwd[f.ID] = true
		if f.MinSeverity != "" {
			if _, err := event.ParseSeverity(f.MinSeverity); err != nil {
				return fmt.Errorf("forward target %q: %w", f.ID, err)
			}
		}
		switch f.Mode {
		case "", "full", "rollup":
		default:
			return fmt.Errorf("forward target %q: mode must be full|rollup (got %q)", f.ID, f.Mode)
		}
	}

	// Intel feed (downward subscriber): url required when enabled.
	if c.IntelFeed.Enabled && c.IntelFeed.URL == "" {
		return fmt.Errorf("intel_feed: url is required when enabled")
	}

	// MISP push: url + key_env required when enabled.
	if c.MISP.Enabled {
		if c.MISP.URL == "" || c.MISP.KeyEnv == "" {
			return fmt.Errorf("misp: url and key_env are required when enabled")
		}
	}

	// Ingest (aggregator endpoint): bind + auth required when enabled — an
	// unauthenticated endpoint that injects events into the store/correlation is
	// not safe, so a token is mandatory.
	if c.Ingest.Enabled {
		if c.Ingest.Bind == "" {
			return fmt.Errorf("ingest: bind is required when enabled")
		}
		if c.Ingest.TokenEnv == "" {
			return fmt.Errorf("ingest: token_env is required when enabled (an unauthenticated ingest endpoint is unsafe)")
		}
		if (c.Ingest.TLSCert == "") != (c.Ingest.TLSKey == "") {
			return fmt.Errorf("ingest: tls_cert and tls_key must be set together")
		}
	}

	// Archeservice role bundles (validated before the listeners they
	// expanded into).
	if err := c.validateArcheservices(); err != nil {
		return err
	}

	// Listeners.
	seenID := map[string]bool{}
	seenBind := map[string]bool{}
	for i, l := range c.Listeners {
		if l.ID == "" {
			return fmt.Errorf("listeners[%d]: id is required", i)
		}
		if seenID[l.ID] {
			return fmt.Errorf("listener id %q duplicated", l.ID)
		}
		seenID[l.ID] = true
		if l.Proto != "tcp" && l.Proto != "udp" {
			return fmt.Errorf("listener %s: proto must be tcp or udp", l.ID)
		}
		if l.Bind == "" {
			return fmt.Errorf("listener %s: bind is required", l.ID)
		}
		key := l.Proto + "://" + l.Bind
		if seenBind[key] {
			return fmt.Errorf("listener %s: duplicate bind %s", l.ID, key)
		}
		seenBind[key] = true
		switch l.Mode {
		case "drop", "banner", "tarpit":
		default:
			return fmt.Errorf("listener %s: unknown mode %q", l.ID, l.Mode)
		}
		// Per-protocol handler whitelist (package-level: see tcpHandlers /
		// udpHandlers, also surfaced by TCPHandlerNames / UDPHandlerNames).
		switch l.Proto {
		case "tcp":
			if !tcpHandlers[l.Handler] {
				return fmt.Errorf("listener %s: handler %q is not valid for tcp", l.ID, l.Handler)
			}
		case "udp":
			if !udpHandlers[l.Handler] {
				return fmt.Errorf("listener %s: handler %q is not valid for udp", l.ID, l.Handler)
			}
		}
		if l.Mode == "banner" && l.Handler == "raw" && l.Banner == "" {
			return fmt.Errorf("listener %s: banner mode with raw handler requires a banner string", l.ID)
		}
		if l.Handler == "lua" && l.Script == "" {
			return fmt.Errorf("listener %s: lua handler requires a script path", l.ID)
		}
		if l.Handler == "scripted" {
			if err := l.Scripted.Validate(); err != nil {
				return fmt.Errorf("listener %s: scripted: %w", l.ID, err)
			}
		}
		if l.Handler == "tls_intercept" {
			ti := l.TLSIntercept
			if ti.ForwardTo != "" {
				if _, _, err := net.SplitHostPort(ti.ForwardTo); err != nil {
					return fmt.Errorf("listener %s: tls_intercept.forward_to must be host:port: %w", l.ID, err)
				}
			} else {
				inner := ti.InnerHandler
				if inner == "" {
					inner = "raw"
				}
				if inner == "tls_intercept" {
					return fmt.Errorf("listener %s: tls_intercept.inner_handler cannot be tls_intercept", l.ID)
				}
				if !tcpHandlers[inner] {
					return fmt.Errorf("listener %s: tls_intercept.inner_handler %q is not a valid tcp handler", l.ID, inner)
				}
			}
		}
		if p := l.SNMP.MIBProfile; p != "" {
			switch p {
			case "minimal", "host", "network", "full":
			default:
				return fmt.Errorf("listener %s: snmp.mib_profile must be minimal|host|network|full (got %q)", l.ID, p)
			}
		}
		if l.Webapp && l.Handler != "http" && l.Handler != "https" {
			return fmt.Errorf("listener %s: webapp requires handler http or https (got %q)", l.ID, l.Handler)
		}
		if l.Mode == "tarpit" {
			if l.Proto != "tcp" {
				return fmt.Errorf("listener %s: tarpit is tcp-only", l.ID)
			}
			switch l.Tarpit.Strategy {
			case "sticky", "trickle", "keepalive",
				"jitter", "backoff", "ssh_banner",
				"http_headers", "http_chunked", "echo", "babble",
				"zipbomb", "zero_window":
			default:
				return fmt.Errorf("listener %s: unknown tarpit strategy %q", l.ID, l.Tarpit.Strategy)
			}
			if l.Tarpit.Strategy == "zipbomb" && l.Tarpit.ZipBomb.DecompressedSize < 0 {
				return fmt.Errorf("listener %s: zipbomb strategy requires tarpit.zipbomb.decompressed_size >= 0", l.ID)
			}
			if l.Tarpit.Strategy == "zero_window" && l.Tarpit.ZeroWindow.ReadBuffer < 0 {
				return fmt.Errorf("listener %s: zero_window strategy requires tarpit.zero_window.read_buffer >= 0", l.ID)
			}
			if l.Tarpit.Strategy == "trickle" && l.Tarpit.Trickle.Text == "" {
				return fmt.Errorf("listener %s: trickle strategy requires tarpit.trickle.text", l.ID)
			}
			if l.Tarpit.Strategy == "backoff" && l.Tarpit.Backoff.Factor != 0 && l.Tarpit.Backoff.Factor < 1 {
				return fmt.Errorf("listener %s: backoff strategy requires tarpit.backoff.factor >= 1", l.ID)
			}
			if l.Tarpit.Strategy == "jitter" && l.Tarpit.Jitter.MinInterval != 0 && l.Tarpit.Jitter.MaxInterval != 0 &&
				l.Tarpit.Jitter.MaxInterval < l.Tarpit.Jitter.MinInterval {
				return fmt.Errorf("listener %s: jitter strategy requires tarpit.jitter.max_interval >= min_interval", l.ID)
			}
		}
		if _, err := event.ParseSeverity(l.Severity); err != nil {
			return fmt.Errorf("listener %s: %w", l.ID, err)
		}
		if l.Archetype != "" && archetype.Lookup(l.Archetype) == nil {
			return fmt.Errorf("listener %s: archetype %q is not a known archetype", l.ID, l.Archetype)
		}
		switch l.AcceptCreds {
		case "", "none", "defaults", "any":
		default:
			return fmt.Errorf("listener %s: accept_creds must be none|defaults|any (got %q)", l.ID, l.AcceptCreds)
		}
		switch l.HTTPS.KeyType {
		case "", "ecdsa", "rsa":
		default:
			return fmt.Errorf("listener %s: https.key_type must be ecdsa|rsa (got %q)", l.ID, l.HTTPS.KeyType)
		}
	}

	// Canaries.
	canID := map[string]bool{}
	for i, ca := range c.Canaries {
		if ca.ID == "" {
			return fmt.Errorf("canaries[%d]: id is required", i)
		}
		if canID[ca.ID] {
			return fmt.Errorf("canary id %q duplicated", ca.ID)
		}
		canID[ca.ID] = true
		if ca.Path == "" {
			return fmt.Errorf("canary %s: path is required", ca.ID)
		}
		for _, evname := range ca.Events {
			switch evname {
			case "write", "remove", "rename", "create", "chmod":
			default:
				return fmt.Errorf("canary %s: unknown event %q", ca.ID, evname)
			}
		}
		if _, err := event.ParseSeverity(ca.Severity); err != nil {
			return fmt.Errorf("canary %s: %w", ca.ID, err)
		}
	}

	// URL canaries.
	urlID := map[string]bool{}
	for i, uc := range c.URLCanaries {
		if uc.ID == "" {
			return fmt.Errorf("url_canaries[%d]: id is required", i)
		}
		if urlID[uc.ID] {
			return fmt.Errorf("url_canary id %q duplicated", uc.ID)
		}
		urlID[uc.ID] = true
		if uc.Path == "" || uc.Path[0] != '/' {
			return fmt.Errorf("url_canary %s: path must start with '/'", uc.ID)
		}
		if _, err := event.ParseSeverity(uc.Severity); err != nil {
			return fmt.Errorf("url_canary %s: %w", uc.ID, err)
		}
	}

	// DNS canaries.
	dnsID := map[string]bool{}
	for i, dc := range c.DNSCanaries {
		if dc.ID == "" {
			return fmt.Errorf("dns_canaries[%d]: id is required", i)
		}
		if dnsID[dc.ID] {
			return fmt.Errorf("dns_canary id %q duplicated", dc.ID)
		}
		dnsID[dc.ID] = true
		if dc.Name == "" {
			return fmt.Errorf("dns_canary %s: name is required", dc.ID)
		}
		if _, err := event.ParseSeverity(dc.Severity); err != nil {
			return fmt.Errorf("dns_canary %s: %w", dc.ID, err)
		}
	}
	if c.DNS.AmplifierDetection.Enabled {
		if _, err := event.ParseSeverity(c.DNS.AmplifierDetection.Severity); err != nil {
			return fmt.Errorf("dns.amplifier_detection: %w", err)
		}
	}

	// Honeynets.
	hnID := map[string]bool{}
	allHostIPs := map[string]bool{}
	for i, hn := range c.Honeynets {
		if hn.ID == "" {
			return fmt.Errorf("honeynets[%d]: id is required", i)
		}
		if hnID[hn.ID] {
			return fmt.Errorf("honeynet id %q duplicated", hn.ID)
		}
		hnID[hn.ID] = true
		if hn.CIDR != "" {
			if _, err := netip.ParsePrefix(hn.CIDR); err != nil {
				return fmt.Errorf("honeynet %s: cidr %q: %w", hn.ID, hn.CIDR, err)
			}
		}
		if hn.Gateway != "" {
			if _, err := netip.ParseAddr(hn.Gateway); err != nil {
				return fmt.Errorf("honeynet %s: gateway %q: %w", hn.ID, hn.Gateway, err)
			}
		}
		hostName := map[string]bool{}
		for hi, host := range hn.Hosts {
			if host.IP == "" {
				return fmt.Errorf("honeynet %s host[%d]: ip is required", hn.ID, hi)
			}
			if _, err := netip.ParseAddr(host.IP); err != nil {
				return fmt.Errorf("honeynet %s host[%d]: ip %q: %w", hn.ID, hi, host.IP, err)
			}
			if allHostIPs[host.IP] {
				return fmt.Errorf("honeynet %s: ip %s appears more than once across all honeynets", hn.ID, host.IP)
			}
			allHostIPs[host.IP] = true
			if host.Hostname != "" {
				if hostName[host.Hostname] {
					return fmt.Errorf("honeynet %s: hostname %q duplicated", hn.ID, host.Hostname)
				}
				hostName[host.Hostname] = true
			}
			if host.Archetype != "" && archetype.Lookup(host.Archetype) == nil {
				return fmt.Errorf("honeynet %s host %s: archetype %q is not a known archetype", hn.ID, host.IP, host.Archetype)
			}
			portSeen := map[int]bool{}
			for si, svc := range host.Services {
				if svc.Port <= 0 || svc.Port > 65535 {
					return fmt.Errorf("honeynet %s host %s service[%d]: bad port %d", hn.ID, host.IP, si, svc.Port)
				}
				if portSeen[svc.Port] {
					return fmt.Errorf("honeynet %s host %s: port %d defined more than once", hn.ID, host.IP, svc.Port)
				}
				portSeen[svc.Port] = true
				if svc.Handler == "" {
					return fmt.Errorf("honeynet %s host %s service[%d]: handler is required", hn.ID, host.IP, si)
				}
			}
		}
	}

	// Sniffer severity.
	if c.Sniffer.Enabled {
		if _, err := event.ParseSeverity(c.Sniffer.Severity); err != nil {
			return fmt.Errorf("sniffer: %w", err)
		}
	}

	// Devices.
	if c.Devices.Enabled && c.Devices.Severity != "" {
		if _, err := event.ParseSeverity(c.Devices.Severity); err != nil {
			return fmt.Errorf("devices.severity: %w", err)
		}
	}
	for i, a := range c.Devices.Allow {
		if _, err := netip.ParsePrefix(a); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(a); err == nil {
			continue
		}
		// Else must be a 12-hex-digit MAC.
		if !looksLikeMAC(a) {
			return fmt.Errorf("devices.allow[%d]: %q is not an IP, CIDR, or MAC", i, a)
		}
	}

	// Correlator severities.
	if c.Correlate.PortScan.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.PortScan.Severity); err != nil {
			return fmt.Errorf("correlate.port_scan: %w", err)
		}
	}
	if c.Correlate.BruteForce.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.BruteForce.Severity); err != nil {
			return fmt.Errorf("correlate.brute_force: %w", err)
		}
	}
	if c.Correlate.SlowScan.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.SlowScan.Severity); err != nil {
			return fmt.Errorf("correlate.slow_scan: %w", err)
		}
	}
	if c.Correlate.PasswordSpray.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.PasswordSpray.Severity); err != nil {
			return fmt.Errorf("correlate.password_spray: %w", err)
		}
	}
	if c.Correlate.CredReuse.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.CredReuse.Severity); err != nil {
			return fmt.Errorf("correlate.credential_reuse: %w", err)
		}
	}
	if c.Correlate.ICMPSweep.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.ICMPSweep.Severity); err != nil {
			return fmt.Errorf("correlate.icmp_sweep: %w", err)
		}
	}

	// Allowlist.
	for i, s := range c.Allowlist {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err2 := netip.ParseAddr(s); err2 != nil {
				return fmt.Errorf("allowlist[%d]: %q is not a valid IP or CIDR", i, s)
			}
		}
	}

	// Channels.
	chanByID := map[string]bool{}
	for i, ch := range c.Channels {
		if ch.ID == "" {
			return fmt.Errorf("channels[%d]: id is required", i)
		}
		if chanByID[ch.ID] {
			return fmt.Errorf("channel id %q duplicated", ch.ID)
		}
		chanByID[ch.ID] = true
		// A disabled channel keeps its id (so routes referencing it still
		// validate) but skips type-specific checks — it can ship
		// half-configured (no broker / secret yet) and stay off.
		if !ch.On() {
			continue
		}
		switch ch.Type {
		case "stdout", "jsonlog", "sqlite":
		case "webhook":
			if ch.URL == "" {
				return fmt.Errorf("channel %s: webhook needs url", ch.ID)
			}
			if !strings.HasPrefix(ch.URL, "http://") && !strings.HasPrefix(ch.URL, "https://") {
				return fmt.Errorf("channel %s: webhook url must be http(s)://", ch.ID)
			}
		case "smtp":
			if ch.Host == "" || ch.Port == 0 || ch.From == "" || len(ch.To) == 0 {
				return fmt.Errorf("channel %s: smtp needs host, port, from, to", ch.ID)
			}
		case "syslog":
			switch ch.Network {
			case "local", "tcp", "udp", "unix", "tls":
			default:
				return fmt.Errorf("channel %s: syslog network must be local|tcp|udp|unix|tls", ch.ID)
			}
			if ch.Network != "local" && ch.Address == "" {
				return fmt.Errorf("channel %s: syslog network=%s requires address", ch.ID, ch.Network)
			}
		case "discord":
			if ch.URL == "" && ch.URLEnv == "" {
				return fmt.Errorf("channel %s: discord needs url (or url_env) — the Discord webhook URL", ch.ID)
			}
		case "twilio":
			if ch.AccountSIDEnv == "" || ch.AuthTokenEnv == "" {
				return fmt.Errorf("channel %s: twilio needs account_sid_env and auth_token_env", ch.ID)
			}
			if ch.From == "" || len(ch.To) == 0 {
				return fmt.Errorf("channel %s: twilio needs from and to", ch.ID)
			}
		case "sns":
			if ch.TopicARN == "" {
				return fmt.Errorf("channel %s: sns needs topic_arn", ch.ID)
			}
			if ch.AccessKeyEnv == "" || ch.SecretKeyEnv == "" {
				return fmt.Errorf("channel %s: sns needs access_key_env and secret_key_env", ch.ID)
			}
		case "snmptrap":
			if ch.Host == "" {
				return fmt.Errorf("channel %s: snmptrap needs host", ch.ID)
			}
		case "mqtt":
			if ch.URL == "" {
				return fmt.Errorf("channel %s: mqtt needs url (e.g. tcp://broker:1883)", ch.ID)
			}
			if ch.QoS < 0 || ch.QoS > 2 {
				return fmt.Errorf("channel %s: mqtt qos must be 0|1|2", ch.ID)
			}
		default:
			return fmt.Errorf("channel %s: unknown type %q", ch.ID, ch.Type)
		}
		if _, err := event.ParseSeverity(ch.MinSeverity); err != nil {
			return fmt.Errorf("channel %s: %w", ch.ID, err)
		}
		switch ch.Format {
		case "", "json", "cef", "leef", "ocsf":
		default:
			return fmt.Errorf("channel %s: unknown format %q (want json | cef | leef | ocsf)", ch.ID, ch.Format)
		}
		if ch.Format != "" && ch.Format != "json" {
			switch ch.Type {
			case "jsonlog", "syslog", "webhook", "smtp", "stdout":
			case "sqlite":
				return fmt.Errorf("channel %s: format=%q not valid for sqlite (sqlite always stores structured rows)", ch.ID, ch.Format)
			case "twilio", "sns", "snmptrap":
				return fmt.Errorf("channel %s: format=%q not valid for %s (channel-specific payload)", ch.ID, ch.Format, ch.Type)
			}
		}
	}

	// DNS amplifier detection defaults.
	if c.DNS.AmplifierDetection.Enabled {
		if c.DNS.AmplifierDetection.Window == 0 {
			c.DNS.AmplifierDetection.Window = 60 * time.Second
		}
		if c.DNS.AmplifierDetection.Queries == 0 {
			c.DNS.AmplifierDetection.Queries = 20
		}
		if c.DNS.AmplifierDetection.Severity == "" {
			c.DNS.AmplifierDetection.Severity = "high"
		}
	}

	// UI.
	if c.UI.Enabled {
		if c.UI.Bind == "" {
			return fmt.Errorf("ui.bind is required when ui.enabled")
		}
		host, _, err := net.SplitHostPort(c.UI.Bind)
		if err != nil {
			return fmt.Errorf("ui.bind: %w", err)
		}
		isLoopback := host == "127.0.0.1" || host == "::1" || host == "localhost"
		hasTLS := c.UI.TLSCert != "" && c.UI.TLSKey != ""
		hasAuth := c.UI.AuthTokenEnv != ""
		if !isLoopback && (!hasTLS || !hasAuth) {
			return fmt.Errorf("ui.bind %q is non-loopback; refusing to start without both ui.tls_cert+ui.tls_key and ui.auth_token_env", c.UI.Bind)
		}
		if hasTLS {
			if _, err := os.Stat(c.UI.TLSCert); err != nil {
				return fmt.Errorf("ui.tls_cert: %w", err)
			}
			if _, err := os.Stat(c.UI.TLSKey); err != nil {
				return fmt.Errorf("ui.tls_key: %w", err)
			}
		}
	}

	// Routes.
	for i, r := range c.Routes {
		if r.Match.Severity != "" {
			if _, _, err := parseSeverityMatch(r.Match.Severity); err != nil {
				return fmt.Errorf("routes[%d]: %w", i, err)
			}
		}
		for _, id := range r.Channels {
			if !chanByID[id] {
				return fmt.Errorf("routes[%d]: references unknown channel %q", i, id)
			}
		}
	}

	// Active-response blocklist.
	if c.Risk.Block.Enabled {
		if !c.Risk.Enabled {
			return fmt.Errorf("risk.block requires risk.enabled (blocking is driven by the risk score)")
		}
		switch c.Risk.Block.Level {
		case "", "elevated", "high", "critical":
		default:
			return fmt.Errorf("risk.block.level must be elevated|high|critical (got %q)", c.Risk.Block.Level)
		}
		for _, n := range c.Risk.Block.NeverBlock {
			if _, _, err := net.ParseCIDR(n); err != nil && net.ParseIP(n) == nil {
				return fmt.Errorf("risk.block.never_block: %q is not an IP or CIDR", n)
			}
		}
	}
	return nil
}

// looksLikeMAC reports whether s is 12 hex digits with optional
// :/-/. separators — used to validate devices.allow MAC entries.
func looksLikeMAC(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			n++
		case c == ':' || c == '-' || c == '.':
		default:
			return false
		}
	}
	return n == 12
}

// parseSeverityMatch parses ">=low" / "<high" / "=critical" into (op, sev).
func parseSeverityMatch(s string) (string, event.Severity, error) {
	s = strings.TrimSpace(s)
	var op, rest string
	switch {
	case strings.HasPrefix(s, ">="), strings.HasPrefix(s, "<="):
		op, rest = s[:2], s[2:]
	case strings.HasPrefix(s, ">"), strings.HasPrefix(s, "<"), strings.HasPrefix(s, "="):
		op, rest = s[:1], s[1:]
	default:
		op, rest = "=", s
	}
	sev, err := event.ParseSeverity(strings.TrimSpace(rest))
	if err != nil {
		return "", 0, fmt.Errorf("invalid severity match %q: %w", s, err)
	}
	return op, sev, nil
}

// SeverityMatches evaluates a parsed match against an event severity.
func SeverityMatches(spec string, sev event.Severity) (bool, error) {
	if spec == "" {
		return true, nil
	}
	op, target, err := parseSeverityMatch(spec)
	if err != nil {
		return false, err
	}
	switch op {
	case "=":
		return sev == target, nil
	case ">":
		return sev > target, nil
	case ">=":
		return sev >= target, nil
	case "<":
		return sev < target, nil
	case "<=":
		return sev <= target, nil
	}
	return false, fmt.Errorf("unknown operator %q", op)
}
