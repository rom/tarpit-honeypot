-- Fake Adobe Commerce / Magento (handler: lua, HTTP). Magento is exploited via
-- CVE-2024-34102 (CosmicSting XXE) and CVE-2022-24086 (mail-template RCE), and
-- the /admin panel is brute-forced. Serves the recognizable storefront + flags
-- the REST/admin endpoints and XXE.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("<!DOCTYPE") and b:find("SYSTEM") then flag("magento-cve-2024-34102-probe") end end
local p = string.lower(path)
flag("magento-access")
if p:find("estimate%-shipping%-methods") then flag("magento-cve-2024-34102-probe") end
if p:find("/admin") then flag("magento-admin-probe") end
local html = "<html><head><title>Home Page</title><meta name='generator' content='Magento'></head><body>Magento</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nSet-Cookie: PHPSESSID=" .. rng:hex(26) .. "; path=/; HttpOnly\r\nX-Magento-Cache-Debug: MISS\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
