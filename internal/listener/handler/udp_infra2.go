package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Second batch of general UDP infrastructure protocol responders. Capture-only
// (no reply) — several are amplification vectors (SLP, XDMCP, pcAnywhere,
// GameSpy) and UDP sources are spoofable, so the sensor decodes + flags the
// probe but never answers.
//
//   slp (427), xdmcp (177), db_lsp (17500), kerberos_udp (88),
//   lantronix_disc (30718), pcanywhere_stat (5632), gamespy (27900),
//   db2_disc (523), bt_dht (6881), rdp_udp (3389)

// slp — Service Location Protocol (UDP 427). A known amplification vector
// (CVE-2023-29552). SrvRqst from an untrusted source is service enumeration.
type slp struct{}

func (s *slp) Name() string { return "slp" }

func (s *slp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "slp-probe")
	if len(payload) >= 2 {
		res.Meta["slp_version"] = payload[0]
		res.Meta["slp_function"] = payload[1]
		if payload[1] == 1 { // SrvRqst
			flagAnomaly(&res, "service-enumeration")
			flagAnomaly(&res, "amplification-probe")
		}
	}
	return res, nil
}

// xdmcp — X Display Manager Control Protocol (UDP 177). Amplification vector;
// a Query opcode enumerates X login managers.
type xdmcp struct{}

func (x *xdmcp) Name() string { return "xdmcp" }

func (x *xdmcp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "xdmcp-probe")
	if len(payload) >= 6 && binary.BigEndian.Uint16(payload[0:2]) == 1 { // version 1
		op := binary.BigEndian.Uint16(payload[2:4])
		res.Meta["xdmcp_opcode"] = op
		if op == 2 || op == 3 { // Query / BroadcastQuery
			flagAnomaly(&res, "amplification-probe")
		}
	}
	return res, nil
}

// dbLSP — Dropbox LAN Sync Discovery (UDP 17500). A JSON beacon that leaks the
// host_int / namespaces of a Dropbox client — useful host fingerprinting.
type dbLSP struct{}

func (d *dbLSP) Name() string { return "db_lsp" }

func (d *dbLSP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "dropbox-lansync-probe")
	if indexFold(string(payload), "host_int") >= 0 {
		res.Meta["dropbox_beacon"] = safe.SanitizeForLog(clipStr(string(payload), 512))
	}
	return res, nil
}

// kerberosUDP — Kerberos over UDP (UDP 88). An AS-REQ from an untrusted source
// is account enumeration / AS-REP roasting recon; we surface the realm text.
type kerberosUDP struct{}

func (k *kerberosUDP) Name() string { return "kerberos_udp" }

func (k *kerberosUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "kerberos-udp-probe")
	// Full classification (KRB5 message type + padata, plus legacy Kerberos 4 /
	// KTH-KRB detection and the roasting / delegation-abuse tells) is shared
	// with the TCP KDC handler. AS-REQ over UDP from an untrusted source is
	// itself pre-auth / AS-REP-roast recon.
	classifyKRB(payload, &res)
	if mt, _ := res.Meta["message_type"].(string); mt != "" {
		res.Meta["krb_msg"] = mt // back-compat alias for the UDP probe
		if mt == "AS-REQ" {
			flagAnomaly(&res, "kerberos-pre-auth-probe")
		}
	}
	// The realm is an uppercase GENERALSTRING in the request — surface the
	// longest printable run as a hint (captured, not authoritative).
	if r := asciiRun(payload); len(r) >= 3 {
		res.Meta["krb_text"] = safe.SanitizeForLog(clipStr(r, 128))
	}
	return res, nil
}

// lantronixDisc — Lantronix device discovery (UDP 30718). The serial-to-Ethernet
// gateways used in ICS/OT answer a 4-byte query that enumerates the device.
type lantronixDisc struct{}

func (l *lantronixDisc) Name() string { return "lantronix_disc" }

func (l *lantronixDisc) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "lantronix-discovery-probe")
	if len(payload) >= 4 {
		res.Meta["lantronix_query"] = "0x" + strconv.FormatInt(int64(binary.BigEndian.Uint32(payload[0:4])), 16)
		flagAnomaly(&res, "device-discovery-probe")
	}
	return res, nil
}

// pcAnywhereStat — Symantec pcAnywhere status (UDP 5632). Amplification vector;
// the "NQ"/"ST" probe enumerates remote-control hosts.
type pcAnywhereStat struct{}

func (p *pcAnywhereStat) Name() string { return "pcanywhere_stat" }

func (p *pcAnywhereStat) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "pcanywhere-probe")
	if hasPrefixFold(string(payload), "NQ") || hasPrefixFold(string(payload), "ST") {
		res.Meta["pcanywhere_query"] = string(payload[:2])
		flagAnomaly(&res, "amplification-probe")
	}
	return res, nil
}

// gamespy — GameSpy / Quake-class server query (UDP 27900). Amplification vector.
type gamespy struct{}

func (g *gamespy) Name() string { return "gamespy" }

func (g *gamespy) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "gamespy-probe")
	body := string(payload)
	if indexFold(body, "\\status\\") >= 0 || indexFold(body, "\\info\\") >= 0 || hasPrefixFold(body, "\xff\xff\xff\xffgetstatus") {
		flagAnomaly(&res, "amplification-probe")
	}
	return res, nil
}

// db2Disc — IBM DB2 discovery (UDP 523, DB2GETADDR). Enumerates DB2 instances.
type db2Disc struct{}

func (d *db2Disc) Name() string { return "db2_disc" }

func (d *db2Disc) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "db2-discovery-probe")
	if indexFold(string(payload), "DB2GETADDR") >= 0 {
		res.Meta["db2_query"] = "DB2GETADDR"
		flagAnomaly(&res, "service-enumeration")
	}
	return res, nil
}

// btDHT — BitTorrent DHT (UDP 6881). A bencoded KRPC "find_node"/"get_peers"
// query mapping the DHT; high-volume from infected/abuse hosts.
type btDHT struct{}

func (b *btDHT) Name() string { return "bt_dht" }

func (b *btDHT) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "bittorrent-dht-probe")
	body := string(payload)
	switch {
	case indexFold(body, "find_node") >= 0:
		res.Meta["dht_query"] = "find_node"
	case indexFold(body, "get_peers") >= 0:
		res.Meta["dht_query"] = "get_peers"
	case indexFold(body, "announce_peer") >= 0:
		res.Meta["dht_query"] = "announce_peer"
	case indexFold(body, "1:q4:ping") >= 0:
		res.Meta["dht_query"] = "ping"
	}
	return res, nil
}

// rdpUDP — RDP over UDP / MS-RDPEUDP (UDP 3389). Decodes the FEC header flags;
// an RDP-UDP probe is remote-desktop reconnaissance.
type rdpUDP struct{}

func (r *rdpUDP) Name() string { return "rdp_udp" }

func (r *rdpUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "rdp-udp-probe")
	if len(payload) >= 4 {
		res.Meta["rdpudp_flags"] = "0x" + strconv.FormatInt(int64(binary.BigEndian.Uint16(payload[2:4])), 16)
		flagAnomaly(&res, "remote-desktop-probe")
	}
	return res, nil
}
