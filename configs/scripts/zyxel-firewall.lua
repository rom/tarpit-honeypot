-- Fake Zyxel firewall / VPN appliance (handler: lua, HTTP). Zyxel USG/ATP/VPN
-- gear is exploited via CVE-2022-30525 (unauth command injection in the
-- /ztp/cgi-bin/handler nebula setup endpoint) and CVE-2023-28771 (IKE), and
-- brute-forced on the web logon. Serves the recognizable Zyxel logon + flags
-- the ZTP handler probe and login.
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
  if body:find("setWanPortSt") or body:find("[`;|]") then flag("zyxel-cve-2022-30525-probe") end
  local u = body:match("[\"']username[\"']%s*:%s*[\"']([^\"']*)") or body:match("Username=([^&]*)")
  if u then meta("form_user", u); flag("zyxel-login-attempt") end
end

local p = string.lower(path)
flag("zyxel-access")
if p:find("/ztp/cgi%-bin") then flag("zyxel-cve-2022-30525-probe") end
if p:find("/cgi%-bin/") or p:find("weblogin") then flag("zyxel-weblogin-probe") end

local html = "<html><head><title>ZyWALL</title></head><body>" ..
  "<div class='login'>Zyxel USG FLEX</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Zyxel\r\nContent-Type: text/html\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
