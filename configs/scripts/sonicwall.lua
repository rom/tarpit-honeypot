-- Fake SonicWall SSL-VPN (handler: lua, HTTPS). Edge VPN appliances are prime
-- initial-access targets. Captures the portal login and flags known CVE paths.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: SonicWALL SSL-VPN Web Server\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("sonicwall-access")
local p = string.lower(path or "/")
if p:find("/cgi%-bin/jarrewrite.sh") then flag("sonicwall-cve-2021-20038-probe")
elseif p:find("/__api__/") then flag("sonicwall-sma-api-probe") end
local u = body:match("username=([^&]*)"); local pw = body:match("password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("sonicwall-login-attempt") end
send("200 OK", "<html><head><title>SonicWall - Virtual Office</title></head><body><form action=/cgi-bin/userLogin method=post><input name=username><input type=password name=password></form></body></html>")
