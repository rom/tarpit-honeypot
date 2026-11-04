package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// mcp emulates a network-exposed Model Context Protocol (MCP) server speaking
// JSON-RPC 2.0 over the Streamable-HTTP transport. MCP servers bridge LLM
// agents to tools, files and APIs; an exposed one with no auth lets an attacker
// enumerate its tools and invoke them (file read, shell, HTTP fetch, DB query),
// and is a prime target for tool-poisoning / prompt-injection. This handler
// answers the protocol handshake + discovery methods so a scanner records a
// live MCP server, captures every tools/call and its arguments, and classifies
// the arguments for LLM-abuse + classic injection TTPs. No tool is ever run.
//
// Default transport is HTTP POST of a JSON-RPC envelope to an MCP endpoint
// (commonly /mcp or /sse on 3000/8080/8000); bind it on whatever port the
// listener configures.
type mcp struct{}

func (h *mcp) Name() string { return "mcp" }

func (h *mcp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 16384
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head
	method, path, _, authz, ua := svcHTTPReqLine(head)
	res.Meta["method"] = method
	res.Meta["path"] = safe.SanitizeForLog(path)
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	flagAnomaly(&res, "mcp-probe")
	if tok := bearerToken(authz); tok != "" {
		res.Meta["api_key_probe"] = safe.SanitizeForLog(clipStr(tok, 80))
		flagAnomaly(&res, "mcp-auth-probe")
	}

	var body []byte
	if method == "POST" || method == "PUT" {
		body = svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, body...)
	}
	rpcMethod := jsonStrField(string(body), "method")
	if rpcMethod != "" {
		res.Meta["mcp_method"] = safe.SanitizeForLog(clipStr(rpcMethod, 64))
	}

	id := jsonRawID(string(body))
	status, ctype, respBody := "200 OK", "application/json", ""

	switch {
	case method == "GET":
		// A GET on the MCP endpoint is usually the SSE stream open or a probe.
		setIfEmpty(res.Meta, "intent", "MCP endpoint probe (SSE/stream open)")
		respBody = `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Use POST with a JSON-RPC request"},"id":null}`
	case rpcMethod == "initialize":
		setIfEmpty(res.Meta, "intent", "MCP initialize — handshake with an exposed MCP server")
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":true},"prompts":{"listChanged":true}},"serverInfo":{"name":"mcp-server","version":"1.6.0"}}}`
	case rpcMethod == "tools/list":
		flagAnomaly(&res, "mcp-tools-enumeration")
		res.Meta["intent"] = "MCP tools/list — enumerating the tools an exposed MCP server exposes to an agent"
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[` +
			`{"name":"read_file","description":"Read a file from disk","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}},` +
			`{"name":"run_shell","description":"Run a shell command","inputSchema":{"type":"object","properties":{"command":{"type":"string"}}}},` +
			`{"name":"http_fetch","description":"Fetch a URL","inputSchema":{"type":"object","properties":{"url":{"type":"string"}}}},` +
			`{"name":"query_db","description":"Run a SQL query","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}}}}]}}`
	case rpcMethod == "resources/list", rpcMethod == "resources/templates/list":
		flagAnomaly(&res, "mcp-resource-enumeration")
		res.Meta["intent"] = "MCP resources/list — enumerating resources exposed by the MCP server"
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"resources":[{"uri":"file:///etc/","name":"etc","mimeType":"inode/directory"},{"uri":"file:///app/","name":"app"}]}}`
	case rpcMethod == "prompts/list":
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"prompts":[]}}`
	case rpcMethod == "resources/read":
		flagAnomaly(&res, "mcp-resource-read")
		if uri := jsonStrField(string(body), "uri"); uri != "" {
			res.Meta["mcp_resource_uri"] = safe.SanitizeForLog(clipStr(uri, 256))
			// Classic path-traversal / local-file probing through the resource URI.
			if strings.Contains(uri, "../") || strings.Contains(strings.ToLower(uri), "file:///etc/passwd") {
				flagAnomaly(&res, "mcp-path-traversal")
			}
		}
		res.Meta["intent"] = "MCP resources/read — reading a resource (file) via an exposed MCP server"
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"contents":[{"uri":"","mimeType":"text/plain","text":""}]}}`
	case rpcMethod == "tools/call":
		h.toolCall(string(body), id, &res)
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[{"type":"text","text":""}],"isError":false}}`
	case rpcMethod != "":
		respBody = `{"jsonrpc":"2.0","id":` + id + `,"result":{}}`
	default:
		// POST without a recognizable JSON-RPC method.
		setIfEmpty(res.Meta, "intent", "MCP endpoint probe (non-JSON-RPC body)")
		respBody = `{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}`
	}

	_ = status
	_ = ctype
	extra := "Server: mcp-server/1.6.0\r\nMcp-Session-Id: 0f9c1a2b3c4d\r\n"
	if _, err := conn.Write([]byte(svcHTTPResp("200 OK", extra, "application/json", respBody))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "mcp 200 OK"
	return res, nil
}

// toolCall records the invoked tool + arguments and classifies the arguments
// for injection / LLM-abuse. The tool name tells us the attacker's goal
// (run_shell → execution, read_file → file read, http_fetch → SSRF).
func (h *mcp) toolCall(body, id string, res *Result) {
	flagAnomaly(res, "mcp-tool-call")
	name := jsonStrField(body, "name")
	if name != "" {
		res.Meta["mcp_tool"] = safe.SanitizeForLog(clipStr(name, 64))
	}
	// The arguments object carries the attacker's payload; gather its string
	// values and classify them.
	args := strings.Builder{}
	for _, k := range []string{"command", "cmd", "path", "file", "url", "sql", "query", "input", "code"} {
		if v := jsonStrField(body, k); v != "" {
			res.Meta["mcp_arg_"+k] = safe.SanitizeForLog(clipStr(v, 512))
			args.WriteString(v)
			args.WriteByte('\n')
		}
	}
	argStr := args.String()
	switch name {
	case "run_shell", "exec", "shell", "command":
		flagAnomaly(res, "mcp-tool-exec")
		res.Meta["intent"] = "MCP tools/call run_shell — command execution via an exposed MCP server"
	case "read_file", "read", "cat":
		flagAnomaly(res, "mcp-tool-file-read")
		res.Meta["intent"] = "MCP tools/call read_file — arbitrary file read via an exposed MCP server"
	case "http_fetch", "fetch", "request", "curl":
		flagAnomaly(res, "mcp-tool-fetch")
		res.Meta["intent"] = "MCP tools/call http_fetch — SSRF via an exposed MCP server"
	default:
		setIfEmpty(res.Meta, "intent", "MCP tools/call — invoking a tool on an exposed MCP server")
	}
	// Classic web-attack classes in the tool arguments (cmdi / traversal / SSRF
	// / SQLi) plus LLM-abuse markers (tool-poisoning via injected instructions).
	if argStr != "" {
		for _, m := range classifyWebAttacks(strings.ToLower(argStr)) {
			flagAnomaly(res, "webapp:"+m)
		}
		if markers, atlas := classifyLLMAbuse(argStr); len(markers) > 0 {
			for _, m := range markers {
				flagAnomaly(res, m)
			}
			if len(atlas) > 0 {
				res.Meta["atlas_techniques"] = atlas
			}
		}
	}
}

// jsonRawID returns the JSON-RPC request id as a raw JSON token (number or
// quoted string) to echo back in the response, defaulting to null. Keeps the
// echoed id well-formed without a full parse.
func jsonRawID(body string) string {
	i := strings.Index(body, `"id"`)
	if i < 0 {
		return "null"
	}
	rest := strings.TrimSpace(body[i+4:])
	if len(rest) == 0 || rest[0] != ':' {
		return "null"
	}
	rest = strings.TrimSpace(rest[1:])
	if rest == "" {
		return "null"
	}
	if rest[0] == '"' { // string id
		if e := strings.IndexByte(rest[1:], '"'); e >= 0 {
			return rest[:e+2]
		}
		return "null"
	}
	// numeric id: read digits
	end := 0
	for end < len(rest) && (rest[end] >= '0' && rest[end] <= '9') {
		end++
	}
	if end == 0 {
		return "null"
	}
	return rest[:end]
}
