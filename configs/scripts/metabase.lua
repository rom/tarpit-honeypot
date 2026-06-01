-- Fake Metabase (handler: lua, HTTP 3000). Exposed Metabase instances are a
-- prime target — CVE-2023-38646 turns a leaked setup-token into pre-auth RCE.
-- Serves the version + session-properties endpoints believably, captures the
-- probed path + any setup-token validation attempt. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^x%-metabase%-session:") then
    meta("metabase_session", (h:gsub("[\r\n]", "")))
    flag("metabase-session-replay")
  end
end

local ver = rng:choice({ "v0.46.6", "v0.47.0", "v0.45.3", "v0.48.1" })
local token = rng:hex(16)
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: nginx\r\n")
  conn:write("Content-Type: application/json; charset=utf-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("metabase-access")
path = path or "/"
local p = string.lower(path)
if p:find("/api/session/properties") then
  flag("metabase-recon")
  -- The setup-token field is exactly what CVE-2023-38646 abuses.
  send("200 OK", '{"version":{"tag":"' .. ver .. '"},"setup-token":"' .. token .. '","engines":{}}')
elseif p:find("/api/setup/validate") or p:find("/api/setup") then
  flag("metabase-setup-token-abuse") -- CVE-2023-38646 pre-auth RCE primitive
  send("400 Bad Request", '{"errors":{"token":"Invalid setup token"}}')
elseif p:find("/api/health") then
  send("200 OK", '{"status":"ok"}')
elseif p:find("/api/") then
  send("401 Unauthorized", '{"errors":{"_error":"Unauthenticated"}}')
else
  send("200 OK", '<html><head><title>Metabase</title></head><body>Loading...</body></html>')
end
