-- Fake Sophos Firewall (XG/SFOS) admin portal (handler: lua, HTTP). Sophos
-- firewalls are exploited via CVE-2022-1040 (auth bypass in the User Portal/
-- Webadmin) and CVE-2020-12271 (SQLi). Serves the recognizable Sophos login +
-- flags the portal endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("sophos-access")
if p:find("/userportal/webpages/myaccount") then flag("sophos-cve-2022-1040-probe") end
if p:find("/webconsole/") or p:find("/userportal/") then flag("sophos-portal-probe") end
local html = "<html><head><title>Sophos</title></head><body>Sophos Firewall</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: xxxxxxxx-xxxxx\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
