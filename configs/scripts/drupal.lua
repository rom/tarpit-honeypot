-- Fake Drupal (handler: lua, HTTP). Drupal is probed for Drupalgeddon
-- (CVE-2018-7600/7602) and the REST RCE (CVE-2019-6340), and /user/login is
-- brute-forced. Serves the recognizable Drupal page + flags the exploit markers.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("#post_render") or b:find("exec") and b:find("#") then flag("drupalgeddon2-probe") end
  local u = b:match("name=([^&]*)") if u then meta("auth_user", u); flag("drupal-login-attempt") end end
local p = string.lower(path)
flag("drupal-access")
if p:find("_format=hal_json") then flag("drupal-cve-2019-6340-probe") end
if p:find("/user/register") and p:find("_format") then flag("drupalgeddon2-probe") end
local ver = rng:choice({ "9.5.11", "10.1.6", "7.98" })
local html = "<html><head><title>Welcome</title><meta name='Generator' content='Drupal " .. ver .. " (https://www.drupal.org)'></head><body>Drupal</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Generator: Drupal " .. ver .. "\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
