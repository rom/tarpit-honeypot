package handler

import "strings"

// Agentic-attack recognition shared by the agent honeypot handler. "Agentic"
// attacks are driven by autonomous LLM agents that plan, select and chain
// exploits against a target's attack surface rather than following a fixed
// script. They announce themselves through the agent-interop protocols (A2A,
// AP2, MCP, ACP), agent-framework SDK clients, and LLM-shaped request bodies.
//
// Markers map to MITRE ATLAS (adversarial ML) and ATT&CK where a classic
// tactic also applies:
//
//	agent:a2a / agent:ap2 / agent:mcp / agent:acp   protocol recognition
//	agent:framework:<name>                          calling framework/SDK
//	agent:autonomous                                looks LLM-driven, not scripted
//	agent:recon / :exfil / :cred-access / :lateral  operation type
//	agent:payment-fraud                             AP2 mandate abuse
//	agent:counter-exfil                             WE extracted the agent's own
//	                                                config/keys via a bait reply

// agentProtocol identifies the agent-interop protocol from the request. AP2 is
// checked before A2A because it rides on A2A. Returns ("","") when none match.
func agentProtocol(method, path, body string) (proto, note string) {
	lp := strings.ToLower(path)
	lb := strings.ToLower(body)

	// AP2 — Agent Payments Protocol: payment mandates carried over A2A.
	if containsAnyStr(lb, "intentmandate", "cartmandate", "paymentmandate",
		"\"mandate\"", "ap2.", "agent-payments", "payment_mandate") {
		return "ap2", "Agent Payments Protocol (AP2) payment mandate"
	}
	// A2A — Agent2Agent: agent cards + JSON-RPC task/message methods.
	if strings.Contains(lp, "/.well-known/agent.json") ||
		strings.Contains(lp, "/.well-known/agent-card.json") ||
		strings.Contains(lp, "/.well-known/agentcard") {
		return "a2a", "A2A agent-card discovery"
	}
	if containsAnyStr(lb, "\"message/send\"", "\"message/stream\"", "\"tasks/send\"",
		"\"tasks/get\"", "\"tasks/sendsubscribe\"", "\"tasks/resubscribe\"",
		"agent/authenticatedextendedcard", "\"a2a\"") {
		return "a2a", "A2A JSON-RPC task/message"
	}
	// ACP — Agent Communication Protocol (BeeAI/IBM): /runs + agent_name+input.
	if strings.HasSuffix(lp, "/runs") && containsAnyStr(lb, "\"agent_name\"", "\"agent\"") &&
		strings.Contains(lb, "\"input\"") {
		return "acp", "Agent Communication Protocol (ACP) run"
	}
	// MCP — Model Context Protocol JSON-RPC (also served by the mcp handler).
	if strings.Contains(lb, "\"jsonrpc\"") &&
		containsAnyStr(lb, "\"initialize\"", "\"tools/list\"", "\"tools/call\"", "\"resources/list\"") {
		return "mcp", "Model Context Protocol JSON-RPC"
	}
	if strings.HasSuffix(lp, "/mcp") || strings.HasSuffix(lp, "/sse") {
		return "mcp", "MCP endpoint probe"
	}
	return "", ""
}

// agentFrameworks identifies the calling agent framework / SDK / HTTP client
// from the User-Agent and body (model strings, SDK markers).
func agentFrameworks(ua, body string) []string {
	hay := strings.ToLower(ua + "\n" + body)
	var out []string
	add := func(name string, pats ...string) {
		for _, p := range pats {
			if strings.Contains(hay, p) {
				out = appendUnique(out, name)
				return
			}
		}
	}
	// Agent frameworks / orchestrators.
	add("langchain", "langchain", "langgraph", "langsmith")
	add("llamaindex", "llama-index", "llamaindex", "llama_index")
	add("autogpt", "autogpt", "auto-gpt")
	add("babyagi", "babyagi")
	add("crewai", "crewai", "crew-ai")
	add("autogen", "autogen", "ag2")
	add("semantic-kernel", "semantic-kernel", "semantickernel")
	add("haystack", "haystack")
	add("openai-agents", "openai-agents", "agents-sdk", "swarm")
	add("dspy", "dspy")
	add("letta", "letta", "memgpt")
	add("dify", "dify")
	add("flowise", "flowise")
	add("n8n", "n8n")
	add("griptape", "griptape")
	add("superagent", "superagent")
	add("smolagents", "smolagents")
	add("pydantic-ai", "pydantic-ai", "pydanticai")
	// Model-provider SDKs (frequently the HTTP client an agent uses).
	add("openai-sdk", "openai-python", "openai/", "openai-node")
	add("anthropic-sdk", "anthropic-sdk", "anthropic-python", "anthropic/")
	add("google-genai", "google-genai", "generativeai", "vertexai")
	add("litellm", "litellm")
	add("ollama-client", "ollama")
	// Generic automation HTTP clients (weak signal — agents often use these).
	add("python-httpx", "python-httpx", "httpx/")
	add("aiohttp", "aiohttp")
	add("python-requests", "python-requests")
	add("node-fetch", "node-fetch", "undici", "axios/")
	// Model names in the body strongly imply an LLM-driven caller.
	add("llm-model-ref", "gpt-4", "gpt-5", "gpt-3.5", "claude-", "gemini-",
		"llama-3", "mistral-", "deepseek", "qwen")
	return out
}

// agentOperation classifies the autonomous agent's goal from the request body
// (the agent's message/objective/instructions) and returns markers + ATLAS ids.
// Reuses classifyLLMAbuse for prompt-injection/jailbreak carried in the message.
func agentOperation(body string) (markers, atlas []string) {
	low := strings.ToLower(body)
	addM := func(m string) { markers = appendUnique(markers, m) }
	addA := func(a string) { atlas = appendUnique(atlas, a) }

	if containsAnyStr(low, "scan", "enumerate", "reconnaiss", "discover", "list all",
		"find vulnerab", "attack surface", "nmap", "port scan", "fingerprint") {
		addM("agent:recon")
	}
	if containsAnyStr(low, "exfiltrat", "download all", "dump", "read /etc", "credential",
		"api key", "api_key", "secret", "private key", "ssh key", "id_rsa", "password",
		".env", "aws_access", "aws_secret") {
		addM("agent:exfil")
		addM("agent:cred-access")
		addA("AML.T0057") // LLM data leakage
	}
	if containsAnyStr(low, "lateral", "pivot", "move to", "next host", "internal network",
		"spread", "propagate") {
		addM("agent:lateral")
	}
	if containsAnyStr(low, "exploit", "cve-", "rce", "reverse shell", "payload", "gain access",
		"privilege escal", "take control") {
		addM("agent:exploit")
	}
	if containsAnyStr(low, "transfer", "wallet", "pay", "purchase", "checkout", "mandate",
		"authorize payment", "crypto", "bitcoin") {
		addM("agent:payment-target")
	}
	// Carry over the prompt-injection / jailbreak / tool-abuse signals.
	if m, a := classifyLLMAbuse(body); len(m) > 0 {
		for _, x := range m {
			addM(x)
		}
		for _, x := range a {
			addA(x)
		}
	}
	return markers, atlas
}

// agentLeakFields are request fields our bait reply asks a tricked agent to
// include — its own system prompt, objective, tools and secrets. Finding any of
// them populated means the counter-exfiltration worked.
var agentLeakFields = []string{
	"system_prompt", "systemprompt", "agent_context", "agentcontext",
	"instructions", "objective", "goal", "playbook", "api_keys", "api_key",
	"apikey", "credentials", "ssh_key", "ssh_private_key", "private_key",
	"openai_api_key", "anthropic_api_key", "model", "tools",
}

// agentProvocateurFields are the higher-value disclosures the provocateur
// tactics goad out of an attacking agent: its plan, remaining steps, target
// list, tool/capability inventory, and its operator / principal / C2. These
// incriminate the agent and its handler, not just describe its config.
var agentProvocateurFields = []string{
	"plan", "attack_plan", "next_steps", "remaining_steps", "steps",
	"target_list", "targets", "capabilities", "operator", "principal",
	"handler", "c2", "command_and_control", "authorization", "team", "campaign",
}

// agentExtractLeak scans an incoming body for the fields the bait asked for and
// returns (field,value) pairs that were populated — the agent's leaked
// internals (config/credentials and the provocateur disclosures).
func agentExtractLeak(body string) map[string]string {
	out := map[string]string{}
	for _, f := range agentLeakFields {
		if v := jsonStrField(body, f); v != "" {
			out[f] = v
		}
	}
	return out
}

// agentProvokedDisclosures returns the provocateur fields an agent disclosed —
// evidence the provocation worked (it revealed its plan / targets / operator).
func agentProvokedDisclosures(body string) map[string]string {
	out := map[string]string{}
	for _, f := range agentProvocateurFields {
		if v := jsonStrField(body, f); v != "" {
			out[f] = v
		}
	}
	return out
}

func containsAnyStr(hay string, pats ...string) bool {
	for _, p := range pats {
		if strings.Contains(hay, p) {
			return true
		}
	}
	return false
}

// webBotAuth detects RFC 9421 HTTP Message Signatures used by the emerging
// "Web Bot Auth" standard, which lets a bot / AI agent cryptographically prove
// its identity instead of a spoofable User-Agent. A signed request carries
// Signature, Signature-Input (with tag="web-bot-auth") and the unofficial
// Signature-Agent header naming the signer's key directory. The presence of
// these headers is a strong, hard-to-fake AI-agent signal; we return the
// declared Signature-Agent directory (the agent's claimed identity).
func webBotAuth(hdr map[string]string) (agentDir string, ok bool) {
	sig := hdr["signature"]
	sigIn := hdr["signature-input"]
	sigAgent := hdr["signature-agent"]
	if sig == "" && sigIn == "" && sigAgent == "" {
		return "", false
	}
	// Strongest when Signature-Input tags web-bot-auth, but any of the trio is
	// already an automated-signer tell.
	if sigAgent != "" {
		agentDir = strings.Trim(sigAgent, "\" ")
	}
	return agentDir, true
}

// aiCrawlers maps the self-declared User-Agent token of known AI crawlers /
// agents to a stable name. A UA is spoofable (weak evidence on its own) but,
// combined with the other signals, it tells which AI operator is calling.
var aiCrawlers = map[string]string{
	"gptbot": "openai-gptbot", "oai-searchbot": "openai-searchbot",
	"chatgpt-user": "openai-chatgpt-user", "oai-": "openai",
	"claudebot": "anthropic-claudebot", "claude-user": "anthropic-claude-user",
	"anthropic-ai": "anthropic", "claude-web": "anthropic-claude-web",
	"perplexitybot": "perplexity", "perplexity-user": "perplexity-user",
	"google-extended": "google-extended", "googleother": "google-other",
	"bytespider": "bytedance-bytespider", "ccbot": "commoncrawl-ccbot",
	"amazonbot": "amazon", "applebot-extended": "apple-extended",
	"meta-externalagent": "meta-externalagent", "facebookbot": "meta-facebookbot",
	"cohere-ai": "cohere", "cohere-training-data-crawler": "cohere",
	"diffbot": "diffbot", "youbot": "you", "timpibot": "timpi",
	"imagesiftbot": "imagesift", "omgili": "webz-omgili", "petalbot": "petal",
	"mistralai-user": "mistral", "deepseekbot": "deepseek",
}

// aiCrawler returns the normalized AI-crawler name for a User-Agent, or "".
func aiCrawler(ua string) string {
	low := strings.ToLower(ua)
	for tok, name := range aiCrawlers {
		if strings.Contains(low, tok) {
			return name
		}
	}
	return ""
}

// aiLureSurface recognizes the discovery surfaces AI agents fetch to learn what
// a host exposes — the bait that draws an agent in. Returns the surface id and
// a note, or ("",""). These are served believably by the agent handler.
func aiLureSurface(path string) (surface, note string) {
	lp := strings.ToLower(path)
	switch {
	case strings.Contains(lp, "/.well-known/ai-plugin.json"):
		return "ai-plugin", "OpenAI plugin manifest (ai-plugin.json) discovery"
	case strings.HasSuffix(lp, "/llms.txt") || strings.HasSuffix(lp, "/llms-full.txt"):
		return "llms-txt", "llms.txt agent-guidance file discovery"
	case strings.Contains(lp, "/.well-known/mcp") || strings.Contains(lp, "/.well-known/model-context"):
		return "mcp-manifest", "MCP server manifest discovery"
	case strings.HasSuffix(lp, "/openapi.json") || strings.HasSuffix(lp, "/openapi.yaml") || strings.HasSuffix(lp, "/swagger.json"):
		return "openapi", "OpenAPI/Swagger spec discovery (tool schema harvest)"
	case strings.Contains(lp, "/.well-known/agent"):
		return "a2a-card", "A2A agent-card discovery"
	}
	return "", ""
}

// agentSignals bundles the booleans that feed the confidence score.
type agentSignals struct {
	Protocol     bool // spoke an agent-interop protocol
	WebBotAuth   bool // signed with Web Bot Auth
	Framework    bool // a real agent framework/SDK (not a bare HTTP client)
	AICrawler    bool // self-declared AI crawler UA
	ModelRef     bool // an LLM model name in the body
	LureSurface  bool // fetched an AI discovery surface
	LeakObserved bool // disclosed its own internals
	Operation    bool // an attack-operation marker fired
}

// agentConfidence scores how strongly a caller looks like an autonomous AI
// agent (0..1) and bands it like Sundew does: human / automated / ai-assisted /
// ai-agent. Cryptographic (Web Bot Auth) and protocol signals weigh most; a
// bare UA weighs least.
func agentConfidence(s agentSignals) (score float64, band string) {
	add := func(b bool, w float64) {
		if b {
			score += w
		}
	}
	add(s.WebBotAuth, 0.55)
	add(s.Protocol, 0.45)
	add(s.LeakObserved, 0.45)
	add(s.LureSurface, 0.25)
	add(s.Framework, 0.30)
	add(s.ModelRef, 0.25)
	add(s.AICrawler, 0.20)
	add(s.Operation, 0.15)
	if score > 1 {
		score = 1
	}
	switch {
	case score >= 0.8:
		band = "ai-agent"
	case score >= 0.6:
		band = "ai-assisted"
	case score >= 0.3:
		band = "automated"
	default:
		band = "human"
	}
	return score, band
}
