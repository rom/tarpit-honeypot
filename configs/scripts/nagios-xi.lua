-- Fake Nagios XI (handler: lua, HTTP). Nagios XI is brute-forced (nagiosadmin) and
-- probed for repeated SQLi/command-injection CVEs in its CGIs. Serves the
-- recognizable login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("nagiosxi-login-attempt") end end
local p = string.lower(path)
flag("nagiosxi-access")
if p:find("/nagiosxi/") then flag("nagiosxi-probe") end
if p:find("/nagios/cgi%-bin/") then flag("nagios-cgi-probe") end
local html = "<html><head><title>Nagios XI</title></head><body>Nagios XI</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
