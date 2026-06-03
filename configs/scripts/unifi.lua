-- Fake Ubiquiti UniFi Network controller (handler: lua, HTTP). The UniFi web app
-- was hit by Log4Shell (CVE-2021-44228 via the login) and is brute-forced.
-- Serves the recognizable UniFi UI + captures the login JSON + flags JNDI.
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
  if b:find("jndi:") then flag("log4shell-attempt") end
  local u = b:match("\"username\"%s*:%s*\"([^\"]*)") if u then meta("auth_user", u); flag("unifi-login-attempt") end end
local p = string.lower(path)
flag("unifi-access")
if p:find("/api/login") or p:find("/api/self") then flag("unifi-api-probe") end
local html = "<html><head><title>UniFi Network</title></head><body><div id='container'>UniFi</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nSet-Cookie: unifises=" .. rng:hex(20) .. "; Path=/; Secure; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
