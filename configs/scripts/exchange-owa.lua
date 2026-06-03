-- Fake Microsoft Exchange OWA / ECP (handler: lua, HTTP). Exchange is hammered
-- for ProxyLogon (CVE-2021-26855 SSRF via /owa + X-AnonResource cookie),
-- ProxyShell (/autodiscover/autodiscover.json?...&Email=...&X-Rps-CAT) and ECP
-- admin access. Serves the recognizable OWA redirect + captures auth and the
-- known exploit paths.
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
  if hl:find("^cookie:") and h:find("X%-AnonResource") then flag("exchange-proxylogon-probe") end
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("exchange-auth-attempt") end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  meta("post_body", conn:read(clen) or "")
end

local p = string.lower(path)
flag("exchange-access")
if p:find("/autodiscover/autodiscover.json") then flag("exchange-proxyshell-probe") end
if p:find("/ecp/") then flag("exchange-ecp-probe") end

if p == "/" or p:find("^/owa") then
  conn:write("HTTP/1.1 302 Found\r\nServer: Microsoft-IIS/10.0\r\n")
  conn:write("Location: /owa/auth/logon.aspx?url=https%3a%2f%2f%2fowa%2f&reason=0\r\n")
  conn:write("X-FEServer: EXCH01\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
else
  local html = "<html><head><title>Outlook</title></head><body>Outlook Web App</body></html>"
  conn:write("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-FEServer: EXCH01\r\n")
  conn:write("Content-Type: text/html\r\nConnection: close\r\nContent-Length: " ..
    tostring(#html) .. "\r\n\r\n" .. html)
end
