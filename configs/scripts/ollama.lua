-- Fake Ollama LLM API (handler: lua, HTTP 11434). Exposed Ollama servers are
-- a fast-growing target (model theft, resource abuse, CVE-2024-37032 path
-- traversal "Probllama"). Answers the version + tags endpoints believably and
-- captures pull/push/generate requests + path-traversal model names. Nothing
-- is executed and no model is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then
    clen = tonumber((h:match(":%s*(%d+)"))) or 0
  end
end

local body = ""
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  body = conn:read(clen) or ""
  meta("ollama_body", body)
  local model = body:match('"model"%s*:%s*"([^"]*)"') or body:match('"name"%s*:%s*"([^"]*)"')
  if model then
    meta("ollama_model", model)
    if model:find("%.%./") or model:find("%.%.\\") then
      flag("ollama-path-traversal") -- CVE-2024-37032 style model name
    end
  end
end

local ver = rng:choice({ "0.1.48", "0.3.6", "0.3.12", "0.1.34" })
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json; charset=utf-8\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

flag("ollama-access")
path = path or "/"
local p = string.lower(path)
if p:find("/api/version") then
  send("200 OK", '{"version":"' .. ver .. '"}')
elseif p:find("/api/tags") then
  flag("ollama-model-enum")
  send("200 OK", '{"models":[]}')
elseif p:find("/api/pull") or p:find("/api/push") or p:find("/api/create") then
  flag("ollama-model-transfer")
  send("200 OK", '{"status":"pulling manifest"}')
elseif p:find("/api/generate") or p:find("/api/chat") then
  flag("ollama-inference-abuse")
  send("404 Not Found", '{"error":"model not found, try pulling it first"}')
else
  send("200 OK", "Ollama is running")
end
