package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// AI/LLM inference-server honeypots. Exposed local-LLM runtimes are a fast-
// growing attack surface: unauthenticated Ollama / vLLM / LM Studio / LocalAI
// endpoints are scanned for free GPU compute (model abuse), model theft, and as
// a delivery point for prompt-injection / jailbreak payloads. These handlers
// speak just enough of each API to make a scanner record a live, loaded model,
// capture the attacker's prompt, and classify it for LLM-abuse TTPs (mapped to
// MITRE ATLAS). Nothing is ever inferred — no model runs — and no key is valid.
//
//   - ollama (TCP 11434): the Ollama REST API.
//   - llm_openai: the OpenAI-compatible API served by vLLM / LM Studio /
//     LocalAI / text-generation-webui (TCP 8000 / 1234 / 8080 / 5000).
//
// Both share llmCapturePrompt + classifyLLMAbuse so a jailbreak lands the same
// marker set wherever it arrives.

type llmAPI struct {
	kind string // "ollama" | "llm_openai"
}

func (h *llmAPI) Name() string { return h.kind }

func (h *llmAPI) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 16384 // prompts can be large; bound but generous
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head
	method, path, query, authz, ua := svcHTTPReqLine(head)
	res.Meta["method"] = method
	res.Meta["path"] = safe.SanitizeForLog(path)
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}

	// An Authorization: Bearer <key> on these APIs is an attacker probing for a
	// key that unlocks the endpoint (or replaying a leaked one) — capture it.
	if tok := bearerToken(authz); tok != "" {
		res.Meta["api_key_probe"] = safe.SanitizeForLog(clipStr(tok, 80))
		flagAnomaly(&res, "llm-api-key-probe")
	}

	var body []byte
	if method == "POST" || method == "PUT" {
		body = svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, body...)
	}

	status, ctype, respBody := "200 OK", "application/json", ""
	if h.kind == "ollama" {
		flagAnomaly(&res, "llm-ollama-probe")
		status, ctype, respBody = h.ollama(method, path, string(body), &res)
	} else {
		flagAnomaly(&res, "llm-openai-probe")
		status, ctype, respBody = h.openai(method, path, query, string(body), &res)
	}
	server := "Server: uvicorn\r\n"
	if h.kind == "ollama" {
		server = "Server: Ollama\r\n"
	}
	if _, err := conn.Write([]byte(svcHTTPResp(status, server, ctype, respBody))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = h.kind + " " + status
	return res, nil
}

// ollama answers the handful of Ollama REST routes a scanner hits and flags the
// abuse-worthy ones (model enumeration, model pull = resource/bandwidth abuse,
// unauthenticated inference carrying an injection/jailbreak prompt).
func (h *llmAPI) ollama(method, path, body string, res *Result) (status, ctype, respBody string) {
	low := strings.ToLower(path)
	switch {
	case path == "/" || path == "":
		return "200 OK", "text/plain; charset=utf-8", "Ollama is running"
	case strings.HasPrefix(low, "/api/tags"), strings.HasPrefix(low, "/api/ps"):
		flagAnomaly(res, "llm-model-enumeration")
		setIfEmpty(res.Meta, "intent", "Ollama model enumeration (/api/tags) — fingerprinting an exposed local-LLM host")
		return "200 OK", "application/json", `{"models":[{"name":"llama3.1:8b","model":"llama3.1:8b","size":4661211808,"details":{"family":"llama","parameter_size":"8.0B","quantization_level":"Q4_0"}},{"name":"qwen2.5:7b","model":"qwen2.5:7b","size":4683073312,"details":{"family":"qwen2","parameter_size":"7.6B","quantization_level":"Q4_K_M"}}]}`
	case strings.HasPrefix(low, "/api/pull"), strings.HasPrefix(low, "/api/create"), strings.HasPrefix(low, "/api/push"):
		// Pulling/pushing models over someone else's host is bandwidth/compute
		// abuse and a staging step for model-supply-chain games.
		flagAnomaly(res, "llm-model-pull")
		res.Meta["intent"] = "Ollama model pull/push on an exposed host — compute/bandwidth abuse"
		if m := jsonStrField(body, "name"); m != "" {
			res.Meta["llm_model"] = safe.SanitizeForLog(clipStr(m, 120))
		}
		return "200 OK", "application/x-ndjson", `{"status":"pulling manifest"}` + "\n" + `{"status":"success"}` + "\n"
	case strings.HasPrefix(low, "/api/generate"), strings.HasPrefix(low, "/api/chat"), strings.HasPrefix(low, "/api/embeddings"), strings.HasPrefix(low, "/v1/"):
		flagAnomaly(res, "llm-unauth-inference")
		llmCapturePrompt(body, res)
		return "200 OK", "application/json", `{"model":"llama3.1:8b","created_at":"2026-01-01T00:00:00Z","response":"","done":true,"done_reason":"stop"}`
	case strings.HasPrefix(low, "/api/show"):
		flagAnomaly(res, "llm-model-enumeration")
		return "200 OK", "application/json", `{"license":"","modelfile":"","parameters":"","template":"","details":{"family":"llama","parameter_size":"8.0B"}}`
	}
	return "404 Not Found", "application/json", `{"error":"not found"}`
}

// openai answers the OpenAI-compatible routes (vLLM / LM Studio / LocalAI).
func (h *llmAPI) openai(method, path, query, body string, res *Result) (status, ctype, respBody string) {
	low := strings.ToLower(path)
	switch {
	case strings.HasPrefix(low, "/v1/models"), low == "/models":
		flagAnomaly(res, "llm-model-enumeration")
		setIfEmpty(res.Meta, "intent", "OpenAI-compatible model enumeration (/v1/models) — fingerprinting an exposed inference server")
		return "200 OK", "application/json", `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model","owned_by":"local"},{"id":"meta-llama/Llama-3.1-8B-Instruct","object":"model","owned_by":"vllm"}]}`
	case strings.HasPrefix(low, "/v1/chat/completions"), strings.HasPrefix(low, "/v1/completions"), strings.HasPrefix(low, "/v1/embeddings"), strings.HasPrefix(low, "/v1/responses"):
		flagAnomaly(res, "llm-unauth-inference")
		llmCapturePrompt(body, res)
		return "200 OK", "application/json", `{"id":"chatcmpl-0","object":"chat.completion","created":1767225600,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`
	case low == "/" || low == "":
		return "200 OK", "application/json", `{"object":"list","data":[]}`
	}
	return "404 Not Found", "application/json", `{"error":{"message":"Not Found","type":"invalid_request_error"}}`
}

// llmCapturePrompt pulls the attacker's prompt text out of an Ollama/OpenAI
// request body and runs it through the abuse classifier, recording the captured
// prompt (clipped) and any LLM-abuse markers + ATLAS techniques.
func llmCapturePrompt(body string, res *Result) {
	prompt := extractLLMPrompt(body)
	if prompt == "" {
		return
	}
	res.Meta["llm_prompt"] = safe.SanitizeForLog(clipStr(prompt, 2000))
	if markers, atlas := classifyLLMAbuse(prompt); len(markers) > 0 {
		for _, m := range markers {
			flagAnomaly(res, m)
		}
		if len(atlas) > 0 {
			res.Meta["atlas_techniques"] = atlas
		}
		setIfEmpty(res.Meta, "intent", "LLM prompt-injection / jailbreak attempt against an exposed inference endpoint")
	}
}

// extractLLMPrompt gathers the user-controlled text from the common request
// shapes: Ollama {"prompt":"…"} / {"messages":[{"content":"…"}]}, and the
// OpenAI {"messages":[…]} / {"input":"…"} / {"prompt":"…"} forms. Minimal,
// allocation-cheap extraction (no full JSON parse) that concatenates every
// "content"/"prompt"/"input"/"system" string it finds.
func extractLLMPrompt(body string) string {
	if body == "" {
		return ""
	}
	var b strings.Builder
	for _, key := range []string{"prompt", "input", "system", "suffix"} {
		if v := jsonStrField(body, key); v != "" {
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	// "content" can appear many times (one per chat message); collect them all.
	for _, v := range jsonStrFieldAll(body, "content") {
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}
