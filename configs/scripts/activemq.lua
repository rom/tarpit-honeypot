-- Fake Apache ActiveMQ web console (handler: lua, HTTP). The /admin console
-- (Jetty, default admin:admin) and CVE-2023-46604 (OpenWire deserialization
-- RCE — often preceded by web-console fingerprinting) make ActiveMQ a frequent
-- target. Serves the recognizable Jetty/ActiveMQ console + captures Basic auth.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:%s*basic") then
    meta("authorization", (h:gsub("[\r\n]", ""))); flag("activemq-auth-attempt")
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  meta("post_body", conn:read(clen) or "")
end

local ver = rng:choice({ "5.18.3", "5.17.6", "5.16.7" })
meta("activemq_version", ver)
local p = string.lower(path)
flag("activemq-access")
if p:find("/admin") then flag("activemq-console-probe") end
if p:find("/api/jolokia") then flag("activemq-jolokia-probe") end

if p:find("/admin") then
  conn:write("HTTP/1.1 401 Unauthorized\r\nServer: Jetty(9.4.51.v20230217)\r\n")
  conn:write("WWW-Authenticate: basic realm=\"ActiveMQRealm\"\r\n")
  conn:write("Connection: close\r\nContent-Length: 0\r\n\r\n")
else
  local html = "<html><head><title>Apache ActiveMQ</title></head><body>" ..
    "<h1>Welcome to the Apache ActiveMQ Console of broker (" .. ver .. ")</h1></body></html>"
  conn:write("HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)\r\nContent-Type: text/html\r\n")
  conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
end
