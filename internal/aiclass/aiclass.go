// Package aiclass is the single source of truth for which protocol handlers are
// AI/LLM/agent decoys — the agentic honeypot surface (autonomous-agent interop,
// LLM inference APIs, MCP tool servers). It mirrors internal/otclass: the
// enricher stamps a unified `ai` flag + `meta:ai` label on these events, and the
// web UI badges the matching service cards, so the whole AI attack surface is
// one pivot.
package aiclass

// Kind is the AI sub-domain of a handler.
type Kind string

const (
	None  Kind = ""
	Agent Kind = "agent" // autonomous-agent interop (A2A / AP2 / ACP / the agent trap)
	LLM   Kind = "llm"   // LLM inference APIs (OpenAI-style, Ollama, generic)
	MCP   Kind = "mcp"   // Model Context Protocol tool servers
)

// handlerKind maps a handler name to its AI sub-domain. TLS variants (…s) and
// the detection-only handlers are listed explicitly so classification never
// depends on string munging. Keep in sync with internal/listener/handler.
var handlerKind = map[string]Kind{
	"agent":        Agent,
	"a2a":          Agent,
	"agentdetect":  Agent,
	"agentsession": Agent,
	"ollama":       LLM,
	"ollamas":      LLM,
	"llm_openai":   LLM,
	"llm_openais":  LLM,
	"llmapi":       LLM,
	"llmdetect":    LLM,
	"mcp":          MCP,
	"mcps":         MCP,
}

// Of returns the AI sub-domain of a handler, or None when it is not AI.
func Of(handler string) Kind { return handlerKind[handler] }

// IsAI reports whether a handler is an AI/LLM/agent decoy.
func IsAI(handler string) bool { return handlerKind[handler] != None }
