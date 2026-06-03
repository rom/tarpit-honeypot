-- Fake VMware NSX-T Manager (handler: lua, HTTP). NSX management plane is probed
-- for Log4Shell (CVE-2021-44228) and API access. Serves the recognizable NSX UI +
-- flags the policy/API endpoints and JNDI payloads.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if h:find("jndi:") then flag("log4shell-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("jndi:") then flag("log4shell-attempt") end end
local p = string.lower(path)
flag("nsx-access")
if p:find("/policy/api/v1") or p:find("/api/v1/") then flag("nsx-api-probe") end
local html = "<html><head><title>NSX</title></head><body>VMware NSX-T Manager</body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
