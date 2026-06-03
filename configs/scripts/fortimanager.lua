-- Fake Fortinet FortiManager (handler: lua, HTTP). FortiManager fgfmd is exploited
-- via CVE-2024-47575 (FortiJump: missing auth on the fgfm management protocol)
-- and the web UI is probed. Serves the recognizable FortiManager login + flags it.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("/sys/login/user") or b:find("\"method\"") then flag("fortimanager-jsonrpc-probe") end end
local p = string.lower(path)
flag("fortimanager-access")
if p:find("/p/login") or p:find("/cgi%-bin/module/flatui_proxy") then flag("fortimanager-login-probe") end
if p:find("/jsonrpc") then flag("fortimanager-cve-2024-47575-probe") end
local html = "<html><head><title>FortiManager</title></head><body>FortiManager</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
