-- Fake JBoss/WildFly (handler: lua, HTTP 8080). jmx-console / invoker / web-
-- console are classic unauth-deploy RCE paths. Flags them; captures mgmt login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("http-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end conn:read(clen) end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: WildFly/26\r\nX-Powered-By: Undertow/1\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("jboss-access")
local p = string.lower(path or "/")
if p:find("jmx%-console") then flag("jboss-jmx-console-probe")
elseif p:find("/invoker/") then flag("jboss-invoker-probe")          -- CVE-2015-7501 deser
elseif p:find("web%-console") then flag("jboss-web-console-probe") end
send("200 OK", "<html><head><title>Welcome to WildFly</title></head><body><h1>Welcome to WildFly</h1><a href=/console>Administration Console</a></body></html>")
