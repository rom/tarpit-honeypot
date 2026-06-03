-- Fake Ignite Realtime Openfire admin console (handler: lua, HTTP). Openfire's
-- admin console is exploited via CVE-2023-32315 (an auth-bypass path traversal
-- through the setup environment — /setup/setup-/%u002e%u002e/.. to reach
-- admin pages) leading to plugin-upload RCE. Serves the recognizable Openfire
-- admin login + flags the traversal.
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
  if u then meta("openfire_user", u); flag("openfire-login-attempt") end
end

local p = string.lower(path)
flag("openfire-access")
if p:find("/setup/setup%-") or p:find("%u002e") or (p:find("/setup/") and p:find("%.%.")) then
  flag("openfire-cve-2023-32315-probe")
end
if p:find("/plugin%-admin") or p:find("uploadplugin") then flag("openfire-plugin-upload-probe") end

local html = "<html><head><title>Openfire Admin Console</title></head><body>" ..
  "<div id='jive-loginVersion'>Openfire 4.7.4</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Jetty(9.4.x)\r\nContent-Type: text/html; charset=UTF-8\r\n")
conn:write("Set-Cookie: JSESSIONID=" .. rng:hex(20) .. "; Path=/; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
