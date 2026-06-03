-- Fake Strapi headless CMS (handler: lua, HTTP). Strapi is exploited via
-- CVE-2023-22894 / CVE-2023-22621 (admin SSTI/auth) and brute-forced on
-- /admin/login. Serves the recognizable Strapi admin + captures the login JSON.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("\"email\"%s*:%s*\"([^\"]*)") if u then meta("auth_user", u); flag("strapi-login-attempt") end end
local p = string.lower(path)
flag("strapi-access")
if p:find("/admin/auth/") or p:find("/admin/login") then flag("strapi-admin-probe") end
if p:find("/api/") and p:find("filters") then flag("strapi-cve-2023-22894-probe") end
local body = '{"data":{"strapiVersion":"4.15.5"}}'
conn:write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
