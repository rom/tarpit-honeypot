-- Fake pfSense webConfigurator (handler: lua, HTTP). The FreeBSD firewall UI is
-- brute-forced (admin/pfsense) and probed for pfBlockerNG RCE (CVE-2022-31814).
-- Serves the recognizable pfSense login + captures creds + flags pfBlockerNG.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("usernamefld=([^&]*)") if u then meta("auth_user", u); flag("pfsense-login-attempt") end end
local p = string.lower(path)
flag("pfsense-access")
if p:find("/pfblockerng/www/") then flag("pfsense-cve-2022-31814-probe") end
local html = "<html><head><title>pfSense - Login</title></head><body><div class='pftitle'>pfSense</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nSet-Cookie: PHPSESSID=" .. rng:hex(13) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
