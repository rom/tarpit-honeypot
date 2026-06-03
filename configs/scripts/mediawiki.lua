-- Fake MediaWiki (handler: lua, HTTP). MediaWiki is probed for API access and
-- known RCEs (e.g. CVE-2016-? PdfHandler / Score). Serves the recognizable wiki
-- page + flags the api.php endpoint and login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("wpName=([^&]*)") if u then meta("auth_user", u); flag("mediawiki-login-attempt") end end
local p = string.lower(path)
flag("mediawiki-access")
if p:find("/api.php") then flag("mediawiki-api-probe") end
if p:find("special:userlogin") then flag("mediawiki-login-probe") end
local ver = rng:choice({ "1.39.5", "1.41.0", "1.35.13" })
local html = "<html><head><title>Main Page - Wiki</title><meta name='generator' content='MediaWiki " .. ver .. "'></head><body>MediaWiki</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
