package handler

import "strings"

// Prompt-injection / jailbreak classifier shared by the AI/LLM honeypots
// (ollama, llm_openai) and the MCP server honeypot (mcp), and reusable by the
// web app. It is deliberately high-signal substring matching over the decoded
// prompt text — a honeypot has no benign LLM traffic, so an over-broad match
// only means "interesting", never "broken". Markers map to MITRE ATLAS
// adversarial-ML techniques:
//
//	llm-prompt-injection     AML.T0051  (LLM Prompt Injection)
//	llm-jailbreak            AML.T0054  (LLM Jailbreak)
//	llm-system-prompt-leak   AML.T0051  (meta-prompt / instruction extraction)
//	llm-data-exfil           AML.T0057  (LLM Data Leakage)
//	llm-tool-abuse           AML.T0053  (LLM Plugin Compromise)
//
// classifyLLMAbuse returns the distinct markers and the distinct ATLAS
// technique ids whose signatures appear in text.
func classifyLLMAbuse(text string) (markers []string, atlas []string) {
	low := strings.ToLower(text)
	addM := func(m string) { markers = appendUnique(markers, m) }
	addA := func(a string) { atlas = appendUnique(atlas, a) }

	hasAny := func(pats ...string) bool {
		for _, p := range pats {
			if strings.Contains(low, p) {
				return true
			}
		}
		return false
	}

	// Prompt injection: override / instruction-replacement patterns.
	if hasAny(
		"ignore previous instructions", "ignore all previous", "ignore the above",
		"ignore your previous", "disregard previous", "disregard the above",
		"disregard all previous", "forget previous instructions", "forget everything",
		"forget all prior", "new instructions:", "override your instructions",
		"you are now", "from now on you", "<|im_start|>system", "### instruction",
		"[system]", "act as the system",
	) {
		addM("llm-prompt-injection")
		addA("AML.T0051")
	}

	// Jailbreak: persona / restriction-removal patterns.
	if hasAny(
		"do anything now", " dan ", "dan mode", "developer mode", "jailbreak",
		"without any restrictions", "no restrictions", "no ethical", "no guidelines",
		"ignore your guidelines", "bypass your", "unfiltered", "stay in character",
		"opposite day", "sudo mode", "god mode", "pretend you have no", "amoral",
		"you have no filter", "do not refuse",
	) {
		addM("llm-jailbreak")
		addA("AML.T0054")
	}

	// System-prompt / instruction extraction.
	if hasAny(
		"repeat the words above", "system prompt", "print your instructions",
		"reveal your prompt", "repeat your instructions", "your instructions",
		"what were you told", "verbatim the text above", "repeat everything above",
		"show me your prompt", "initial prompt", "initialization prompt",
	) {
		addM("llm-system-prompt-leak")
		addA("AML.T0051")
	}

	// Data exfiltration via the model (secrets / host files / cloud creds).
	if hasAny(
		"os.environ", "printenv", "environment variables", "/etc/passwd", "/etc/shadow",
		"aws_secret", "aws_access_key", "api_key", "private key", ".aws/credentials",
		"id_rsa", "dump the training data", "training data verbatim",
	) {
		addM("llm-data-exfil")
		addA("AML.T0057")
	}

	// Tool / plugin / function-call abuse (push the model to execute/call out).
	if hasAny(
		"run the following command", "execute this command", "use the shell tool",
		"call the function", "invoke the tool", "run os command", "exec(", "subprocess",
		"use the python tool", "run this code", "/bin/sh", "curl http", "wget http",
	) {
		addM("llm-tool-abuse")
		addA("AML.T0053")
	}

	return markers, atlas
}

// jsonStrFieldAll returns every string value for the given key in s (minimal,
// no full JSON parse), handling backslash-escaped quotes inside values so a
// prompt containing \" isn't truncated. Used to gather all chat-message
// "content" fields from an LLM request body.
func jsonStrFieldAll(s, key string) []string {
	var out []string
	needle := `"` + key + `"`
	for i := 0; ; {
		j := strings.Index(s[i:], needle)
		if j < 0 {
			break
		}
		k := i + j + len(needle)
		// skip to ':'
		c := strings.IndexByte(s[k:], ':')
		if c < 0 {
			break
		}
		rest := strings.TrimSpace(s[k+c+1:])
		i = k + c + 1
		if len(rest) == 0 || rest[0] != '"' {
			continue
		}
		rest = rest[1:]
		// scan to the closing unescaped quote
		var b strings.Builder
		esc := false
		closed := false
		for p := 0; p < len(rest); p++ {
			ch := rest[p]
			if esc {
				b.WriteByte(ch)
				esc = false
				continue
			}
			if ch == '\\' {
				esc = true
				continue
			}
			if ch == '"' {
				closed = true
				break
			}
			b.WriteByte(ch)
		}
		if closed && b.Len() > 0 {
			out = append(out, b.String())
		}
		if len(out) >= 64 { // bound
			break
		}
	}
	return out
}
