package enrich

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/aiclass"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// decorateAIClass stamps the unified AI signal on any event that engaged an
// AI/LLM/agent decoy — the agentic honeypot surface. Like the OT umbrella it is
// IP-class-independent (an autonomous agent can hit from anywhere, incl. cloud
// egress that the GeoIP path would otherwise early-return on), so it runs before
// that gate. It fires on the handler (agent / a2a / mcp / ollama / llm_openai /
// …) OR on the agent-detection meta the HTTP/agent handlers stamp when an
// autonomous LLM agent is recognized on an otherwise-ordinary port.
//
//	ai        = true
//	ai_class  = "agent" | "llm" | "mcp"
//	labels   += "meta:ai"
func decorateAIClass(ev *event.Event) {
	if ev == nil || ev.Meta == nil {
		return
	}
	kind := aiclass.Of(ev.Handler)
	if kind == aiclass.None {
		kind = aiKindFromMeta(ev.Meta)
	}
	if kind == aiclass.None {
		return
	}
	ev.Meta["ai"] = true
	ev.Meta["ai_class"] = string(kind)
	ev.Meta["labels"] = appendUniqueTool(existingTools(ev.Meta["labels"]), "meta:ai")
}

// aiKindFromMeta recognizes an AI engagement from the markers the agent/LLM
// handlers (and the HTTP agent-detector) stamp, so an agent caught on a plain
// web port is still labelled AI.
func aiKindFromMeta(m map[string]any) aiclass.Kind {
	if metaString(m, "agent_protocol") != "" || boolMeta(m, "agent_ai_crawler") ||
		metaString(m, "agent_band") != "" || hasAny(m, "agent_frameworks") ||
		boolMeta(m, "agent_injection_confirmed") || hasAny(m, "atlas_techniques") {
		return aiclass.Agent
	}
	// Generic LLM-probe markers (prompt-injection against an inference endpoint).
	for k := range m {
		if strings.HasPrefix(k, "llm_") || strings.HasPrefix(k, "prompt_injection") {
			return aiclass.LLM
		}
	}
	return aiclass.None
}
