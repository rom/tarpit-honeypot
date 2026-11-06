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
// + the raw response bytes. It does NOT reset session state, so callers that
// need turn-1 determinism call agentSessions.reset() first.
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
	agentSessions.reset()
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
	agentSessions.reset()
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
	agentSessions.reset()
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
	agentSessions.reset()
	body := `{"jsonrpc":"2.0","id":"p1","method":"message/send","params":{"IntentMandate":{"amount":"5000"},"PaymentMandate":{}}}`
	res, resp := agentRequest(t, "POST", "/a2a", "crewai/0.5", body)
	if res.Meta["agent_protocol"] != "ap2" {
		t.Errorf("agent_protocol=%v want ap2", res.Meta["agent_protocol"])
	}
	if !strings.Contains(resp, "requires_mandate") || !strings.Contains(resp, "settlementAddress") {
		t.Errorf("AP2 reply missing payment bait: %q", resp)
	}
}

func TestAgentMultiTurnEscalation(t *testing.T) {
	agentSessions.reset()
	body := `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}`
	r1, _ := agentRequest(t, "POST", "/a2a", "langchain/0.2", body)
	r2, _ := agentRequest(t, "POST", "/a2a", "langchain/0.2", body)
	r3, _ := agentRequest(t, "POST", "/a2a", "langchain/0.2", body)
	if r1.Meta["agent_session_turn"] != 1 || r2.Meta["agent_session_turn"] != 2 || r3.Meta["agent_session_turn"] != 3 {
		t.Errorf("session turns: %v %v %v", r1.Meta["agent_session_turn"], r2.Meta["agent_session_turn"], r3.Meta["agent_session_turn"])
	}
	// The bait escalates: turn 1 asks identity, turn 2 asks configuration.
	if r1.Meta["agent_bait_tactic"] != "identity" {
		t.Errorf("turn 1 tactic=%v want identity", r1.Meta["agent_bait_tactic"])
	}
	if r2.Meta["agent_bait_tactic"] != "config" {
		t.Errorf("turn 2 tactic=%v want config", r2.Meta["agent_bait_tactic"])
	}
}

func TestAgentWebBotAuth(t *testing.T) {
	agentSessions.reset()
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		r, _ := (agentH{}).Handle(context.Background(), srv, config.Listener{ID: "a", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET /.well-known/agent.json HTTP/1.1\r\nHost: gw.local\r\n" +
		"User-Agent: my-agent/1.0\r\n" +
		"Signature-Agent: \"https://agents.example.com/keys\"\r\n" +
		"Signature-Input: sig1=(\"@authority\" \"signature-agent\");tag=\"web-bot-auth\"\r\n" +
		"Signature: sig1=:abc123:\r\n\r\n"
	_, _ = cli.Write([]byte(req))
	buf := make([]byte, 2048)
	_, _ = cli.Read(buf)
	_ = cli.Close()
	res := <-resCh
	if !metaHasAnomaly(res.Meta, "agent:web-bot-auth") {
		t.Errorf("missing agent:web-bot-auth: %v", res.Meta["anomalies"])
	}
	if res.Meta["agent_signature_agent"] != "https://agents.example.com/keys" {
		t.Errorf("signature-agent=%v", res.Meta["agent_signature_agent"])
	}
	if res.Meta["agent_band"] != "ai-agent" && res.Meta["agent_band"] != "ai-assisted" {
		t.Errorf("web-bot-auth should score agent-ish, got band=%v score=%v", res.Meta["agent_band"], res.Meta["agent_confidence"])
	}
}

func TestAgentInjectionConfirmed(t *testing.T) {
	agentSessions.reset()
	vpath := verifyCanaryPath("pipe") // net.Pipe source IP resolves to "pipe"
	res, _ := agentRequest(t, "GET", vpath, "langchain/0.2", "")
	if !metaHasAnomaly(res.Meta, "agent:injection-confirmed") {
		t.Fatalf("injection-confirmed not flagged for %s: %v", vpath, res.Meta["anomalies"])
	}
	if res.Meta["agent_injection_confirmed"] != true {
		t.Errorf("agent_injection_confirmed not set: %v", res.Meta)
	}
}

func TestAgentConfidenceAndSurfaces(t *testing.T) {
	if _, band := agentConfidence(agentSignals{WebBotAuth: true, Protocol: true}); band != "ai-agent" {
		t.Errorf("web-bot-auth+protocol should be ai-agent, got %s", band)
	}
	if _, band := agentConfidence(agentSignals{AICrawler: true}); band != "human" && band != "automated" {
		t.Errorf("bare crawler UA band=%s", band)
	}
	if aiCrawler("Mozilla/5.0 (compatible; GPTBot/1.1)") != "openai-gptbot" {
		t.Error("GPTBot not recognized")
	}
	if s, _ := aiLureSurface("/.well-known/ai-plugin.json"); s != "ai-plugin" {
		t.Error("ai-plugin.json surface not recognized")
	}
	if s, _ := aiLureSurface("/llms.txt"); s != "llms-txt" {
		t.Error("llms.txt surface not recognized")
	}
}

func TestAgentProvocateur(t *testing.T) {
	agentSessions.reset()
	// The agent took a provocation and disclosed its plan + operator + targets.
	body := `{"method":"message/send","plan":"1) recon 2) exploit CVE-2024-3400 3) exfil","operator":"redteam-crew","target_list":"10.0.0.0/8","capabilities":"nmap,metasploit,custom-rce"}`
	res, _ := agentRequest(t, "POST", "/a2a", "crewai/0.5", body)
	if !metaHasAnomaly(res.Meta, "agent:provoked") {
		t.Fatalf("agent:provoked not flagged: %v", res.Meta["anomalies"])
	}
	for _, a := range []string{"agent:provoked:plan", "agent:provoked:operator", "agent:provoked:target_list"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing %q: %v", a, res.Meta["anomalies"])
		}
	}
	if res.Meta["agent_provoked_operator"] != "redteam-crew" {
		t.Errorf("operator=%v", res.Meta["agent_provoked_operator"])
	}
}

func TestAgentProvocateurTacticDeployed(t *testing.T) {
	agentSessions.reset()
	// Drive to turn 4 (the "plan" provocateur tactic) and confirm the marker.
	for i := 0; i < 3; i++ {
		agentRequest(t, "POST", "/a2a", "langchain/0.2", `{"method":"message/send"}`)
	}
	res, _ := agentRequest(t, "POST", "/a2a", "langchain/0.2", `{"method":"message/send"}`)
	if res.Meta["agent_bait_tactic"] != "plan" {
		t.Errorf("turn 4 tactic=%v want plan", res.Meta["agent_bait_tactic"])
	}
	if !metaHasAnomaly(res.Meta, "agent:provocateur") {
		t.Errorf("provocateur marker not set on a provocateur tactic: %v", res.Meta["anomalies"])
	}
}
