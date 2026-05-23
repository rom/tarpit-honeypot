package handler

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// runDevsvc drives one handler over a pipe with the given client request and
// returns the server-side Result plus the bytes the handler wrote back.
func runDevsvc(t *testing.T, h Handler, req []byte) (Result, []byte) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: h.Name(), ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = h.Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write(req)
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	client.Close()
	<-done
	return res, buf[:n]
}

func TestJDWPHandshakeFlagged(t *testing.T) {
	res, reply := runDevsvc(t, &jdwp{}, []byte("JDWP-Handshake"))
	if string(reply) != "JDWP-Handshake" {
		t.Errorf("reply = %q; want JDWP-Handshake", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "jdwp-handshake-attempt") {
		t.Errorf("anomalies = %v; want jdwp-handshake-attempt", anoms)
	}
}

func TestRMIProbeAcked(t *testing.T) {
	req := []byte("JRMI")
	req = binary.BigEndian.AppendUint16(req, 2) // version
	req = append(req, 0x4b)                     // StreamProtocol
	res, reply := runDevsvc(t, &rmiRegistry{}, req)
	if len(reply) == 0 || reply[0] != 0x4e {
		t.Errorf("reply = %v; want ProtocolAck 0x4e", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "rmi-probe") {
		t.Errorf("anomalies = %v; want rmi-probe", anoms)
	}
}

func TestGitRequestParsed(t *testing.T) {
	body := "git-upload-pack /secret.git\x00host=git.example.com\x00"
	req := []byte(fmt.Sprintf("%04x%s", len(body)+4, body))
	res, reply := runDevsvc(t, &gitDaemon{}, req)
	if res.Meta["git_service"] != "git-upload-pack" || res.Meta["git_repo"] != "/secret.git" {
		t.Errorf("git meta = %v; want service/repo parsed", res.Meta)
	}
	if res.Meta["git_host"] != "git.example.com" {
		t.Errorf("git_host = %v", res.Meta["git_host"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "git-request") {
		t.Errorf("anomalies = %v; want git-request", anoms)
	}
	if len(reply) < 4 {
		t.Errorf("expected a git error pkt-line reply, got %q", reply)
	}
}

func TestGitPushFlagged(t *testing.T) {
	body := "git-receive-pack /x.git\x00host=h\x00"
	req := []byte(fmt.Sprintf("%04x%s", len(body)+4, body))
	res, _ := runDevsvc(t, &gitDaemon{}, req)
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "git-push-attempt") {
		t.Errorf("anomalies = %v; want git-push-attempt", anoms)
	}
}

func TestZooKeeperRuok(t *testing.T) {
	res, reply := runDevsvc(t, &zookeeper{}, []byte("ruok"))
	if string(reply) != "imok" {
		t.Errorf("reply = %q; want imok", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "zookeeper-fourletter") {
		t.Errorf("anomalies = %v; want zookeeper-fourletter", anoms)
	}
}

func TestKafkaApiVersionsParsed(t *testing.T) {
	req := binary.BigEndian.AppendUint32(nil, 8) // size (rest)
	req = binary.BigEndian.AppendUint16(req, 18) // apiKey ApiVersions
	req = binary.BigEndian.AppendUint16(req, 0)  // apiVersion
	req = binary.BigEndian.AppendUint32(req, 99) // correlationId
	res, reply := runDevsvc(t, &kafkaBroker{}, req)
	if res.Meta["kafka_api"] != "ApiVersions" {
		t.Errorf("kafka_api = %v; want ApiVersions", res.Meta["kafka_api"])
	}
	if len(reply) >= 8 {
		if corr := binary.BigEndian.Uint32(reply[4:8]); corr != 99 {
			t.Errorf("echoed correlationId = %d; want 99", corr)
		}
	} else {
		t.Errorf("kafka reply too short: %v", reply)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "kafka-request") {
		t.Errorf("anomalies = %v; want kafka-request", anoms)
	}
}
