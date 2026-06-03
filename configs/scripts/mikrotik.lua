-- Fake MikroTik RouterOS webfig (handler: lua, HTTP). RouterOS is heavily
-- exploited (CVE-2018-14847 cred disclosure, botnet recruitment). Captures the
-- webfig/ login and flags the Winbox-over-HTTP probe.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: MikroTik HttpProxy\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("mikrotik-access")
local p = string.lower(path or "/")
if p:find("/jsproxy") or p:find("/winbox") then flag("mikrotik-winbox-probe") end
local u = body:match("name=([^&]*)"); local pw = body:match("password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("mikrotik-login-attempt") end
send("200 OK", "<html><head><title>RouterOS</title></head><body><h1>RouterOS v6.49.7</h1><form action=/jsproxy method=post><input name=name><input type=password name=password></form></body></html>")
