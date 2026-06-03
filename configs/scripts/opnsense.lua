-- Fake OPNsense web GUI (handler: lua, HTTP). The pfSense-fork firewall UI is
-- brute-forced (root/opnsense) and API-probed. Serves the recognizable OPNsense
-- login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("usernamefld=([^&]*)") if u then meta("auth_user", u); flag("opnsense-login-attempt") end end
local p = string.lower(path)
flag("opnsense-access")
if p:find("/api/core/firmware") or p:find("/api/") then flag("opnsense-api-probe") end
local html = "<html><head><title>Login | OPNsense</title></head><body><div class='login-content'>OPNsense</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: OPNsense\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
