-- Fake Fortinet FortiOS SSL-VPN portal (handler: lua, HTTP). The /remote/login
-- portal is mass-scanned, and CVE-2018-13379 (path traversal to
-- /remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession leaking
-- credentials) is one of the most-exploited bugs in the wild. Serves the
-- recognizable FortiGate portal + captures login POSTs and the traversal probe.
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
  local u = body:match("username=([^&]*)")
  local p2 = body:match("[^_]credential=([^&]*)") or body:match("password=([^&]*)")
  if u then meta("form_user", u) end
  if p2 then meta("form_pass", p2) end
  if u or p2 then flag("fortios-vpn-login-attempt") end
end

local p = string.lower(path)
flag("fortios-vpn-access")
if p:find("/remote/fgt_lang") and p:find("%.%.") then flag("fortios-cve-2018-13379-probe") end
if p:find("/remote/login") then flag("fortios-vpn-portal-probe") end

local html = "<html><head><title>Please Login</title>" ..
  "<link href='/sslvpn/css/login.css' rel='stylesheet'></head><body>" ..
  "<div class='sslvpn-login'>FortiGate SSL-VPN</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: xxxxxxxx-xxxxx\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: SVPNCOOKIE=" .. rng:hex(20) .. "; path=/; secure; httponly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
