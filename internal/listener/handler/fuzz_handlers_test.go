package handler

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// fuzzConn is a net.Conn that serves a fixed buffer to Read (then EOF) and
// discards Writes. Deadlines are no-ops. It lets us drive a real handler's
// Handle(ctx, conn, cfg) with arbitrary attacker bytes and no network.
type fuzzConn struct {
	data []byte
	pos  int
}

func (c *fuzzConn) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.pos:])
	c.pos += n
	return n, nil
}
func (c *fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) LocalAddr() net.Addr              { return fuzzAddr{} }
func (c *fuzzConn) RemoteAddr() net.Addr             { return fuzzAddr{} }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr struct{}

func (fuzzAddr) Network() string { return "tcp" }
func (fuzzAddr) String() string  { return "198.51.100.7:40000" }

// fuzzPacketConn is a net.PacketConn whose WriteTo discards (so a UDP
// handler's reply goes nowhere) and ReadFrom returns EOF.
type fuzzPacketConn struct{}

func (fuzzPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, io.EOF }
func (fuzzPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (fuzzPacketConn) Close() error                              { return nil }
func (fuzzPacketConn) LocalAddr() net.Addr                       { return fuzzAddr{} }
func (fuzzPacketConn) SetDeadline(time.Time) error               { return nil }
func (fuzzPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (fuzzPacketConn) SetWriteDeadline(time.Time) error          { return nil }

// fuzzTCPNames is every TCP handler we drive end-to-end. lua is excluded
// (it needs a script path); https / ssh_interactive are excluded from the
// hot fuzz loop because their parsing is dominated by stdlib crypto
// (already fuzzed upstream) and a TLS/SSH keygen+handshake per input would
// throttle throughput — their app-layer parsers (JA3/JA4/HASSH) have their
// own fuzz targets in internal/fingerprint.
var fuzzTCPNames = []string{
	"raw", "ssh", "http", "telnet", "ftp", "ftp_files", "smb", "vnc",
	"smtp_recv", "rdp", "winrm", "dcerpc", "ldap", "kerberos", "postgres",
	"mysql", "mssql", "oracle_tns", "redis", "syslog_tcp", "rtsp",
	"dockerapi", "melsec", "xmpp", "amqp", "ipp", "modbus", "s7",
	"s7comm_plus", "iec104", "mqtt", "opcua", "ethernetip", "dnp3",
	"ge_srtp", "codesys", "atg", "fox", "hartip", "pcworx", "mms",
	"teamviewer", "anydesk", "openvpn", "citrix_ica",
	"vmware_authd", "x11", "rlogin", "nx", "redfish",
	"intel_amt", "ilo", "idrac", "esxi", "fortinet", "pulse",
	"citrix_gateway", "horizon", "moxa_mgmt", "scripted",
}

func fuzzDeps(dir string) Deps {
	return Deps{
		Identity:    identity.New("fuzz"),
		DataDir:     dir,
		AcceptCreds: "any",
		HoneynetView: HoneynetSnapshot{Hosts: []HoneynetHost{
			{IP: "10.0.0.5", Hostname: "fuzz-host", Services: []HoneynetService{{Port: 80, Handler: "http"}}},
		}},
		// Exercise the scripted match loop across every mode.
		Scripted: config.ScriptedProto{
			Greeting: "READY\\r\\n",
			Rules: []config.ScriptedRule{
				{Match: "prefix", Value: "GET", Respond: "ok\\r\\n"},
				{Match: "contains", Value: "admin", Anomaly: "scripted-admin", Respond: "no\\r\\n"},
				{Match: "regex", Value: "[0-9]{3,}", Respond: "num\\r\\n"},
				{Match: "hex_prefix", Value: "00ff", RespondHex: "01", Close: true},
			},
			Default: "?\\r\\n",
		},
	}
}

// buildTCPHandlers builds every fuzzable TCP handler once. Handlers that
// fail to construct (missing deps) are skipped.
func buildTCPHandlers(dir string) ([]Handler, []string) {
	var hs []Handler
	var names []string
	for _, n := range fuzzTCPNames {
		h, err := Get(n, fuzzDeps(dir))
		if err != nil {
			continue
		}
		hs = append(hs, h)
		names = append(names, n)
	}
	return hs, names
}

// FuzzTCPHandlers drives every TCP handler's Handle() with arbitrary bytes.
// The first byte selects the handler; the rest is the connection input. A
// panic (OOB slice, etc.) or a hang fails the input. Run:
//
//	go test ./internal/listener/handler -run x -fuzz FuzzTCPHandlers -fuzztime 60s
func FuzzTCPHandlers(f *testing.F) {
	hs, _ := buildTCPHandlers(f.TempDir())
	if len(hs) == 0 {
		f.Skip("no handlers built")
	}
	// Seeds: a selector byte + a representative protocol snippet.
	f.Add([]byte{0})
	f.Add([]byte{26, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a}) // modbus-ish
	f.Add(append([]byte{2}, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")...))                  // http
	f.Add([]byte{27, 0x03, 0x00, 0x00, 0x16, 0x11, 0xe0})                                     // s7/TPKT-ish
	f.Add([]byte{30, 0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00})                         // dnp3-ish
	cfg := config.Listener{ReadTimeout: 500 * time.Millisecond, ReadBytes: 8192}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		h := hs[int(data[0])%len(hs)]
		conn := &fuzzConn{data: data[1:]}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// A panic here is a real bug — let it fail the fuzz input.
		_, _ = h.Handle(ctx, conn, cfg)
	})
}

// fuzzUDPNames is every UDP handler (from GetUDP).
var fuzzUDPNames = []string{
	"raw", "snmp", "ntp", "bacnet", "tftp", "ipmi", "syslog_udp", "radius",
	"sip", "ssdp", "cldap", "llmnr", "nbns", "fins", "coap", "knx", "dhcp",
	"dns", "echo", "discard", "daytime", "qotd", "chargen", "time",
}

func buildUDPHandlers(dir string) []UDPHandler {
	var hs []UDPHandler
	for _, n := range fuzzUDPNames {
		h, err := GetUDP(n, fuzzDeps(dir))
		if err != nil {
			continue
		}
		hs = append(hs, h)
	}
	return hs
}

// FuzzUDPHandlers drives every UDP handler's Handle() with an arbitrary
// datagram. The first byte selects the handler; the rest is the payload.
// Run:
//
//	go test ./internal/listener/handler -run x -fuzz FuzzUDPHandlers -fuzztime 60s
func FuzzUDPHandlers(f *testing.F) {
	hs := buildUDPHandlers(f.TempDir())
	if len(hs) == 0 {
		f.Skip("no udp handlers built")
	}
	f.Add([]byte{0})
	f.Add([]byte{1, 0x30, 0x26, 0x02, 0x01, 0x01})                                            // snmp-ish (BER)
	f.Add([]byte{2, 0x1b, 0x00, 0x00, 0x00})                                                  // ntp mode 3-ish
	f.Add([]byte{17, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // dns query-ish
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}
	pc := fuzzPacketConn{}
	cfg := config.Listener{ReadTimeout: 500 * time.Millisecond, ReadBytes: 8192}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		h := hs[int(data[0])%len(hs)]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = h.Handle(ctx, data[1:], src, pc, cfg)
	})
}
