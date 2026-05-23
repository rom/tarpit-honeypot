package handler

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// This file holds developer- / data-infrastructure protocol decoys that are
// frequent intrusion targets: the Java Debug Wire Protocol and RMI registry
// (both classic unauthenticated-RCE / deserialization vectors), the git
// daemon protocol, ZooKeeper's four-letter admin words, and the Kafka wire
// protocol. Each reads a bounded request, answers just enough to look real
// to a banner-grab / scanner, captures what was sent, and flags the
// high-signal markers.

// readCapped reads up to len(buf) bytes after stamping the read deadline and
// returns the captured slice (nil on no data).
func readCapped(conn net.Conn, cfg config.Listener, buf []byte) []byte {
	withTimeout(conn, cfg.ReadTimeout)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

// --- JDWP (Java Debug Wire Protocol, 8000/8787/5005) ---------------------
//
// A debug port left exposed is unauthenticated remote code execution: the
// attacker completes the 14-byte "JDWP-Handshake" then issues
// VirtualMachine commands. We answer the handshake (so a scanner confirms
// "JDWP open") and flag it — there is no legitimate reason to reach this.

type jdwp struct{}

func (h *jdwp) Name() string { return "jdwp" }

func (h *jdwp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	const hs = "JDWP-Handshake"
	got := readCapped(conn, cfg, make([]byte, 64))
	res.Payload = got
	if len(got) >= len(hs) && string(got[:len(hs)]) == hs {
		_, _ = conn.Write([]byte(hs))
		res.BannerSent = hs
		res.Meta["jdwp"] = "handshake-completed"
		flagAnomaly(&res, "jdwp-handshake-attempt")
	} else {
		flagAnomaly(&res, "jdwp-probe")
	}
	return res, nil
}

// --- Java RMI registry (1099) --------------------------------------------
//
// The RMI registry is the entry point for Java-deserialization RCE
// (ysoserial). The JRMI handshake is magic "JRMI" + version(2) +
// protocol(1); the registry replies ProtocolAck (0x4e) + the caller's
// endpoint. We send a believable ProtocolAck and flag the probe.

type rmiRegistry struct{}

func (h *rmiRegistry) Name() string { return "rmi" }

func (h *rmiRegistry) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 64))
	res.Payload = got
	if len(got) >= 7 && string(got[:4]) == "JRMI" {
		res.Meta["rmi_version"] = int(binary.BigEndian.Uint16(got[4:6]))
		res.Meta["rmi_protocol"] = int(got[6])
		// ProtocolAck (0x4e) + UTF endpoint hostname + int32 port.
		host := "localhost"
		out := []byte{0x4e}
		out = binary.BigEndian.AppendUint16(out, uint16(len(host)))
		out = append(out, host...)
		out = binary.BigEndian.AppendUint32(out, 0)
		_, _ = conn.Write(out)
		res.BannerSent = "rmi protocol-ack"
	}
	flagAnomaly(&res, "rmi-probe")
	return res, nil
}

// --- git daemon protocol (9418) ------------------------------------------
//
// The git:// transport sends one pkt-line: 4 hex length + "git-upload-pack
// /repo\0host=...\0". We parse the service + repo + host, capture them, and
// answer a git error pkt-line (no repo is served). A receive-pack request
// is an attempted push (supply-chain), flagged separately.

type gitDaemon struct{}

func (h *gitDaemon) Name() string { return "git" }

func (h *gitDaemon) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	if len(got) >= 4 {
		// Body after the 4-hex length prefix, NUL-delimited fields.
		body := string(got[4:])
		fields := strings.Split(body, "\x00")
		req := strings.TrimSpace(fields[0])
		res.Meta["git_request"] = req
		if i := strings.IndexByte(req, ' '); i > 0 {
			res.Meta["git_service"] = req[:i]
			res.Meta["git_repo"] = req[i+1:]
		}
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "host=") {
				res.Meta["git_host"] = strings.TrimPrefix(f, "host=")
			}
		}
		if strings.Contains(req, "git-receive-pack") {
			flagAnomaly(&res, "git-push-attempt")
		}
	}
	flagAnomaly(&res, "git-request")
	msg := "ERR access denied or repository not found"
	_, _ = conn.Write([]byte(fmt.Sprintf("%04x%s", len(msg)+4, msg)))
	res.BannerSent = "git error pkt-line"
	return res, nil
}

// --- Apache ZooKeeper (2181) ---------------------------------------------
//
// ZooKeeper answers unauthenticated "four-letter words" that leak cluster
// state — `ruok`->`imok`, `stat`/`mntr`/`envi`/`conf`/`srvr` dump config and
// metrics. Walking them is recon against the ensemble.

type zookeeper struct{}

func (h *zookeeper) Name() string { return "zookeeper" }

func (h *zookeeper) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 16))
	res.Payload = got
	cmd := ""
	if len(got) >= 4 {
		cmd = strings.ToLower(string(got[:4]))
	}
	res.Meta["zk_command"] = cmd
	var reply string
	switch cmd {
	case "ruok":
		reply = "imok"
	case "srvr", "stat":
		reply = "Zookeeper version: 3.8.4-d9ca..., built on 2024-02-12\n" +
			"Latency min/avg/max: 0/0/12\nReceived: 1842\nSent: 1841\n" +
			"Connections: 3\nOutstanding: 0\nMode: leader\nNode count: 412\n"
	case "mntr":
		reply = "zk_version\t3.8.4\nzk_avg_latency\t0\nzk_max_latency\t12\n" +
			"zk_packets_received\t1842\nzk_num_alive_connections\t3\n" +
			"zk_server_state\tleader\nzk_znode_count\t412\n"
	case "envi":
		reply = "Environment:\nzookeeper.version=3.8.4\nhost.name=zk-01\n" +
			"java.version=11.0.22\nos.name=Linux\n"
	case "conf":
		reply = "clientPort=2181\ndataDir=/var/lib/zookeeper\ntickTime=2000\n" +
			"maxClientCnxns=60\nserverId=1\n"
	default:
		if cmd != "" {
			flagAnomaly(&res, "zookeeper-fourletter")
		}
		return res, nil
	}
	_, _ = conn.Write([]byte(reply))
	res.BannerSent = "zookeeper " + cmd
	flagAnomaly(&res, "zookeeper-fourletter")
	return res, nil
}

// --- Apache Kafka wire protocol (9092) -----------------------------------
//
// Kafka requests are [int32 size][int16 apiKey][int16 apiVersion][int32
// correlationId][...]. We parse the API key (Metadata/ApiVersions are the
// scanner staples), capture it, and echo a minimal correlated response so
// the client sees a live broker.

var kafkaAPINames = map[int16]string{
	0: "Produce", 1: "Fetch", 3: "Metadata", 8: "OffsetCommit",
	9: "OffsetFetch", 10: "FindCoordinator", 18: "ApiVersions",
	19: "CreateTopics", 20: "DeleteTopics",
}

type kafkaBroker struct{}

func (h *kafkaBroker) Name() string { return "kafka" }

func (h *kafkaBroker) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "kafka-request")
	if len(got) < 12 {
		return res, nil
	}
	apiKey := int16(binary.BigEndian.Uint16(got[4:6]))
	apiVer := int16(binary.BigEndian.Uint16(got[6:8]))
	corrID := binary.BigEndian.Uint32(got[8:12])
	res.Meta["kafka_api_key"] = apiKey
	res.Meta["kafka_api_version"] = apiVer
	if name, ok := kafkaAPINames[apiKey]; ok {
		res.Meta["kafka_api"] = name
	}
	// Minimal response: [int32 size][int32 correlationId][int16 errorCode=0].
	body := make([]byte, 0, 6)
	body = binary.BigEndian.AppendUint32(body, corrID)
	body = binary.BigEndian.AppendUint16(body, 0)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	out = append(out, body...)
	_, _ = conn.Write(out)
	res.BannerSent = "kafka response"
	return res, nil
}
