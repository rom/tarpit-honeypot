-- Fake misp web UI (handler: lua, HTTP). Recognizable banner + endpoint flags for
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
flag("misp-probe")
if p:find("/api", 1, true) then flag("misp-api-probe") end
if p:find("login", 1, true) or method == "POST" then flag("misp-auth-attempt") end
if p:find("/users/login", 1, true) then flag("misp-login-probe") end
local body = '<!DOCTYPE html><title>MISP</title><div class="loginPanel">Welcome to MISP'
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
