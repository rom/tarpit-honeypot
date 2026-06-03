-- Fake SolarWinds Orion Platform (handler: lua, HTTP). Orion (Network/Server &
-- Application Monitor) is a high-value enterprise-management target: the
-- SUNBURST supply-chain campaign + CVE-2020-10148 (auth bypass via crafted
-- /WebResource.axd?...&_VIEWSTATE paths reaching /api endpoints) drew sustained
-- scanning. Serves the recognizable Orion login + flags the bypass paths.
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
  local u = body:match("[Uu]sername=([^&]*)")
  if u then meta("form_user", u); flag("solarwinds-login-attempt") end
end

local ver = rng:choice({ "2020.2.1", "2019.4", "2020.2.4" })
meta("orion_version", ver)
local p = string.lower(path)
flag("solarwinds-access")
if p:find("/webresource.axd") or p:find("/scriptresource.axd") then flag("solarwinds-cve-2020-10148-probe") end
if p:find("/orion/") or p:find("/api2/") then flag("solarwinds-orion-probe") end

local html = "<html><head><title>SolarWinds Orion</title></head><body>" ..
  "<form action='/Orion/Login.aspx' method='post'>SolarWinds Platform " .. ver ..
  "</form></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5\r\nX-Powered-By: ASP.NET\r\n")
conn:write("Content-Type: text/html\r\nSet-Cookie: ASP.NET_SessionId=" .. rng:hex(12) ..
  "; path=/; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
