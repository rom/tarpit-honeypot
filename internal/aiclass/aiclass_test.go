package aiclass

import "testing"

func TestClassification(t *testing.T) {
	cases := map[string]Kind{
		"agent": Agent, "a2a": Agent, "agentdetect": Agent,
		"mcp": MCP, "mcps": MCP,
		"ollama": LLM, "ollamas": LLM, "llm_openai": LLM, "llm_openais": LLM, "llmdetect": LLM,
		"ssh": None, "modbus": None, "http": None, "": None,
	}
	for h, want := range cases {
		if got := Of(h); got != want {
			t.Errorf("Of(%q) = %q, want %q", h, got, want)
		}
		if IsAI(h) != (want != None) {
			t.Errorf("IsAI(%q) = %v, want %v", h, IsAI(h), want != None)
		}
	}
}
