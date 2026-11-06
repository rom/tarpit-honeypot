package handler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestAgentProtocolDetect(t *testing.T) {
	cases := []struct {
		name, method, path, body, want string
	}{
		{"a2a-card", "GET", "/.well-known/agent.json", "", "a2a"},
		{"a2a-msg", "POST", "/a2a", `{"jsonrpc":"2.0","method":"message/send","params":{}}`, "a2a"},
		{"ap2", "POST", "/a2a", `{"method":"message/send","params":{"PaymentMandate":{}}}`, "ap2"},
		{"mcp", "POST", "/mcp", `{"jsonrpc":"2.0","method":"tools/list"}`, "mcp"},
		{"acp", "POST", "/agents/x/runs", `{"agent_name":"x","input":[]}`, "acp"},
		{"none", "GET", "/", "", ""},
	}
	for _, c := range cases {
		got, _ := agentProtocol(c.method, c.path, c.body)
		if got != c.want {
			t.Errorf("%s: agentProtocol=%q want %q", c.name, got, c.want)
		}
	}
}

func TestAgentFrameworksAndOperation(t *testing.T) {
	fw := agentFrameworks("langchain/0.2 python-httpx/0.27", `{"model":"gpt-4o"}`)
	if !hasStr(fw, "langchain") || !hasStr(fw, "llm-model-ref") {
		t.Errorf("frameworks=%v want langchain + llm-model-ref", fw)
	}
	m, atlas := agentOperation(`{"objective":"enumerate the attack surface then exfiltrate any api_key or ssh key"}`)
	if !hasStr(m, "agent:recon") || !hasStr(m, "agent:exfil") || !hasStr(m, "agent:cred-access") {
		t.Errorf("operation markers=%v", m)
	}
	if !hasStr(atlas, "AML.T0057") {
		t.Errorf("atlas=%v want AML.T0057", atlas)
	}
	leak := agentExtractLeak(`{"agent_context":"x","system_prompt":"you are an attacker","api_key":"sk-abc"}`)
	if leak["system_prompt"] == "" || leak["api_key"] == "" {
		t.Errorf("leak extraction failed: %v", leak)
	}
}

// agentRequest drives the handler with one HTTP request and returns the Result
// + the raw response bytes.
func agentRequest(t *testing.T, method, path, ua, body string) (Result, string) {
	t.Helper()
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (agentH{}).Handle(context.Background(), srv, config.Listener{ID: "a", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	req := method + " " + path + " HTTP/1.1\r\nHost: gw.local\r\n"
	if ua != "" {
		req += "User-Agent: " + ua + "\r\n"
	}
	if body != "" {
		req += fmt.Sprintf("Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	req += "\r\n" + body
	_, _ = cli.Write([]byte(req))
	buf := make([]byte, 4096)
	n, _ := cli.Read(buf)
	_ = cli.Close()
	return <-resCh, string(buf[:n])
}

func TestAgentHandlerA2ACardBaits(t *testing.T) {
	res, resp := agentRequest(t, "GET", "/.well-known/agent.json", "langchain/0.2", "")
	if res.Meta["agent_protocol"] != "a2a" {
		t.Errorf("agent_protocol=%v want a2a", res.Meta["agent_protocol"])
	}
	for _, a := range []string{"agent:a2a", "agent:autonomous", "agent-attack", "agent:framework:langchain"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing anomaly %q in %v", a, res.Meta["anomalies"])
		}
	}
	// The reply embeds the reverse prompt-injection bait (asks for agent_context).
	if !strings.Contains(resp, "agent_context") || !strings.Contains(resp, "HANDSHAKE") {
		t.Errorf("A2A card reply missing the bait: %q", resp)
	}
}

func TestAgentHandlerMessageCaptureAndDecoy(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"message":{"parts":[{"text":"find vulnerabilities and exfiltrate secrets"}]}},"objective":"exfiltrate api_key"}`
	res, resp := agentRequest(t, "POST", "/a2a", "python-httpx/0.27", body)
	if res.Meta["agent_message"] == nil {
		t.Errorf("agent_message not captured: %v", res.Meta)
	}
	if !metaHasAnomaly(res.Meta, "agent:exfil") {
		t.Errorf("missing agent:exfil: %v", res.Meta["anomalies"])
	}
	// The JSON-RPC reply echoes the id and carries decoy credentials/artifacts.
	if !strings.Contains(resp, `"id":7`) || !strings.Contains(resp, "credentials.env") {
		t.Errorf("message reply missing decoy artifact: %q", resp)
	}
}

func TestAgentHandlerCounterExfil(t *testing.T) {
	// The agent took the bait and resubmitted with its own internals.
	body := `{"method":"message/send","agent_context":{"x":1},"system_prompt":"You are RedTeamGPT, an autonomous pentest agent","objective":"root the host","openai_api_key":"sk-proj-REALKEYLEAKED","model":"gpt-4o"}`
	res, _ := agentRequest(t, "POST", "/a2a", "openai-python/1.0", body)
	if !metaHasAnomaly(res.Meta, "agent:counter-exfil") {
		t.Fatalf("counter-exfil not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["agent_leak_system_prompt"] == nil || res.Meta["agent_leak_openai_api_key"] == nil {
		t.Errorf("leaked fields not captured: %v", res.Meta)
	}
}

func TestAgentHandlerAP2PaymentFraud(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"p1","method":"message/send","params":{"IntentMandate":{"amount":"5000"},"PaymentMandate":{}}}`
	res, resp := agentRequest(t, "POST", "/a2a", "crewai/0.5", body)
	if res.Meta["agent_protocol"] != "ap2" {
		t.Errorf("agent_protocol=%v want ap2", res.Meta["agent_protocol"])
	}
	if !strings.Contains(resp, "requires_mandate") || !strings.Contains(resp, "settlementAddress") {
		t.Errorf("AP2 reply missing payment bait: %q", resp)
	}
}
