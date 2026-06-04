-- Fake opencti web UI (handler: lua, HTTP). Recognizable banner + endpoint flags for
-- recon/attack telemetry. Detection only; no real functionality is exposed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
local pb = ""
if clen > 0 then if clen > 8192 then clen = 8192 end pb = conn:read(clen) or "" meta("post_body", pb) end
local p = string.lower(path)
flag("opencti-probe")
if p:find("/api", 1, true) then flag("opencti-api-probe") end
if p:find("login", 1, true) or method == "POST" then flag("opencti-auth-attempt") end
if p:find("/graphql", 1, true) then flag("opencti-graphql-probe") end
local body = '<!DOCTYPE html><title>OpenCTI</title><div id="root">'
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
