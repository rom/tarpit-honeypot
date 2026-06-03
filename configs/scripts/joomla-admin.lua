-- Fake Joomla! administrator (handler: lua, HTTP). The /administrator login is
-- brute-forced and Joomla is probed for CVE-2023-23752 (config disclosure) and
-- object-injection CVEs. Serves the recognizable Joomla admin + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("joomla-login-attempt") end end
local p = string.lower(path)
flag("joomla-access")
if p:find("/api/index.php/v1/config/application") and p:find("public=true") then flag("joomla-cve-2023-23752-probe") end
if p:find("/administrator") then flag("joomla-admin-probe") end
local html = "<html><head><title>Joomla Administration Login</title><meta name='generator' content='Joomla! - Open Source Content Management'></head><body>Joomla!</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nSet-Cookie: " .. rng:hex(26) .. "=" .. rng:hex(26) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
