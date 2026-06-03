-- Fake Dolibarr ERP/CRM (handler: lua, HTTP). Dolibarr is exploited via
-- CVE-2023-30253 (PHP code injection via case-altered <?PHP) and brute-forced.
-- Serves the recognizable login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("<?php") or b:find("<?PHP") then flag("dolibarr-cve-2023-30253-probe") end
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("dolibarr-login-attempt") end end
local p = string.lower(path)
flag("dolibarr-access")
if p:find("/index.php") and p:find("dol") then flag("dolibarr-probe") end
local html = "<html><head><title>Dolibarr</title></head><body>Dolibarr ERP/CRM</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nSet-Cookie: DOLSESSID_" .. rng:hex(8) .. "=" .. rng:hex(26) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
