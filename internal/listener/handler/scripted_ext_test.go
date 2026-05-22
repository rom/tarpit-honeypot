package handler

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestScriptedMatchModesAndStages(t *testing.T) {
	h, err := compileScripted(config.ScriptedProto{
		Greeting: "HI\\r\\n",
		Rules: []config.ScriptedRule{
			{Match: "suffix", Value: "END", Respond: "S\\r\\n"},
			{Match: "icontains", Value: "help", Respond: "H\\r\\n"},
			{Match: "iprefix", Value: "get ", Respond: "G\\r\\n"},
			{Match: "prefix", Value: "CMD", Stage: "authed", Respond: "OK\\r\\n"},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// suffix ignores trailing CRLF.
	if r := h.match([]byte("data END\r\n"), ""); r == nil || r.mode != "suffix" {
		t.Errorf("suffix did not match")
	}
	// case-insensitive contains / prefix.
	if r := h.match([]byte("PLEASE HELP ME"), ""); r == nil || r.mode != "icontains" {
		t.Errorf("icontains did not match")
	}
	if r := h.match([]byte("GET /x"), ""); r == nil || r.mode != "iprefix" {
		t.Errorf("iprefix did not match")
	}
	// A staged rule only matches in its stage.
	if r := h.match([]byte("CMD run"), ""); r != nil {
		t.Errorf("staged rule matched in wrong stage: %v", r.mode)
	}
	if r := h.match([]byte("CMD run"), "authed"); r == nil {
		t.Errorf("staged rule did not match in its stage")
	}
}

func TestScriptedCredentialCapture(t *testing.T) {
	h, err := compileScripted(config.ScriptedProto{
		Greeting: "login:\\r\\n",
		Rules: []config.ScriptedRule{
			{Match: "regex", Value: `^USER (\S+)`, Capture: "user", SetStage: "havuser", Respond: "pass:\\r\\n"},
			{Match: "regex", Value: `^PASS (\S+)`, Capture: "pass", Respond: "bad\\r\\n"},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Duplex: the client waits for each prompt before sending the next line,
	// so USER and PASS arrive as separate reads (separate matches).
	client, server := pipePair(t)
	cfg := config.Listener{ReadBytes: 256, ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := h.Handle(context.Background(), server, cfg)
		resC <- r
	}()
	br := bufio.NewReader(client)
	_, _ = br.ReadString('\n') // greeting
	_, _ = client.Write([]byte("USER admin\r\n"))
	_, _ = br.ReadString('\n') // pass prompt
	_, _ = client.Write([]byte("PASS s3cret\r\n"))
	_, _ = br.ReadString('\n') // bad
	_ = client.Close()
	res := <-resC
	if res.Meta["auth_user"] != "admin" || res.Meta["auth_pass"] != "s3cret" {
		t.Errorf("capture failed: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestScriptedCaptureValidation(t *testing.T) {
	// capture requires a regex match.
	err := config.ScriptedProto{
		Rules: []config.ScriptedRule{{Match: "prefix", Value: "X", Capture: "user"}},
	}.Validate()
	if err == nil {
		t.Errorf("capture on a non-regex rule should fail validation")
	}
	// invalid capture target.
	err = config.ScriptedProto{
		Rules: []config.ScriptedRule{{Match: "regex", Value: "(.*)", Capture: "token"}},
	}.Validate()
	if err == nil {
		t.Errorf("capture must be user|pass")
	}
}
