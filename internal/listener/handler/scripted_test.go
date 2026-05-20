package handler

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestScriptedGreetingAndRules(t *testing.T) {
	spec := config.ScriptedProto{
		Greeting: "WELCOME\\r\\n",
		Rules: []config.ScriptedRule{
			{Match: "prefix", Value: "PING", Respond: "PONG\\r\\n"},
			{Match: "contains", Value: "secret", Anomaly: "scripted-secret-probe", Respond: "?\\r\\n"},
			{Match: "regex", Value: "^QUIT", Respond: "BYE\\r\\n", Close: true},
		},
		Default: "ERR\\r\\n",
	}
	h, err := compileScripted(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	client, server := pipePair(t)
	cfg := config.Listener{ReadBytes: 256, ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := h.Handle(context.Background(), server, cfg)
		resC <- r
	}()
	br := bufio.NewReader(client)

	if line, _ := br.ReadString('\n'); line != "WELCOME\r\n" {
		t.Fatalf("greeting = %q", line)
	}
	steps := []struct{ send, want string }{
		{"PING\r\n", "PONG\r\n"},    // prefix
		{"FOO\r\n", "ERR\r\n"},      // default
		{"the secret\r\n", "?\r\n"}, // contains + anomaly
	}
	for _, s := range steps {
		if _, err := client.Write([]byte(s.send)); err != nil {
			t.Fatalf("write %q: %v", s.send, err)
		}
		if line, _ := br.ReadString('\n'); line != s.want {
			t.Errorf("send %q: got %q; want %q", s.send, line, s.want)
		}
	}
	// QUIT closes the connection after BYE.
	_, _ = client.Write([]byte("QUIT now\r\n"))
	if line, _ := br.ReadString('\n'); line != "BYE\r\n" {
		t.Errorf("QUIT resp = %q; want BYE", line)
	}
	_ = client.Close()
	r := <-resC
	anoms, _ := r.Meta["anomalies"].([]string)
	if !containsStr(anoms, "scripted-secret-probe") {
		t.Errorf("anomalies = %v; want scripted-secret-probe", anoms)
	}
}

// hex_prefix matches binary protocols on a leading byte sequence.
func TestScriptedHexPrefix(t *testing.T) {
	spec := config.ScriptedProto{
		Rules: []config.ScriptedRule{
			{Match: "hex_prefix", Value: "deadbeef", RespondHex: "cafe", Close: true},
		},
	}
	h, err := compileScripted(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	client, server := pipePair(t)
	cfg := config.Listener{ReadBytes: 64, ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := h.Handle(context.Background(), server, cfg)
		resC <- r
	}()
	if _, err := client.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	n, _ := client.Read(buf)
	if n != 2 || buf[0] != 0xca || buf[1] != 0xfe {
		t.Errorf("response = % x; want ca fe", buf[:n])
	}
	_ = client.Close()
	<-resC
}

// A spec with neither greeting nor rules must be rejected at compile time.
func TestScriptedCompileRejectsEmpty(t *testing.T) {
	if _, err := compileScripted(config.ScriptedProto{}); err == nil {
		t.Error("compileScripted(empty) returned nil error")
	}
}
