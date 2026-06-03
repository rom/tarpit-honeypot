-- Fake Spring Boot app + Actuator (handler: lua, HTTP). Spring Boot apps leak
-- secrets through unauthenticated actuator endpoints (/actuator/env, /heapdump,
-- /gateway/routes) and are hit by Spring4Shell (CVE-2022-22965 — class-loader
-- manipulation via class.module.classLoader request params). Serves the
-- recognizable Whitelabel page and flags actuator probing + Spring4Shell.
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
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("class%.module%.classLoader") then flag("spring4shell-probe") end
end

local p = string.lower(path)
flag("spring-boot-access")
if p:find("class%.module%.classloader") then flag("spring4shell-probe") end
if p:find("/actuator/env") or p:find("/actuator/heapdump") then flag("spring-actuator-secrets-probe") end
if p:find("/actuator/gateway") then flag("spring-cloud-gateway-probe") end
if p:find("/actuator") then flag("spring-actuator-probe") end

local body = ""
if p:find("/actuator/env") then
  body = '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}'
  conn:write("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.spring-boot.actuator.v3+json\r\n")
else
  body = "<html><body><h1>Whitelabel Error Page</h1><p>There was an unexpected error (type=Not Found, status=404).</p></body></html>"
  conn:write("HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n")
end
conn:write("Connection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
