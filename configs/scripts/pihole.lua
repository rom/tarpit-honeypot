-- Fake Pi-hole admin (handler: lua, HTTP). Captures the admin login POST and
-- flags API-token theft attempts.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: lighttpd/1.4.59\r\nX-Powered-By: PHP/7.4\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("pihole-access")
local p = string.lower(path or "/")
if p:find("api%.php") and p:find("auth") then flag("pihole-api-token-probe") end
local pw = body:match("pw=([^&]*)")
if pw then meta("auth_pass", pw); flag("pihole-login-attempt") end
send("200 OK", "<html><head><title>Pi-hole Admin Console</title></head><body><form method=post><input type=password name=pw></form><div>Pi-hole v5.18.2</div></body></html>")
