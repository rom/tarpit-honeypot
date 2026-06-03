-- Fake OpenWRT LuCI (handler: lua, HTTP). The web UI of countless home/SOHO
-- routers; default-cred and CVE targets. Captures the /cgi-bin/luci login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: uhttpd\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("luci-access")
local u = body:match("luci_username=([^&]*)") or body:match("username=([^&]*)")
local pw = body:match("luci_password=([^&]*)") or body:match("password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("luci-login-attempt") end
send("200 OK", "<html><head><title>OpenWrt - LuCI</title></head><body><h2>Authorization Required</h2><form action=/cgi-bin/luci method=post><input name=luci_username><input type=password name=luci_password></form></body></html>")
