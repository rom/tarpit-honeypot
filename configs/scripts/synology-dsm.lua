-- Fake Synology DiskStation Manager (handler: lua, HTTP). NAS web UI mass-probed
-- for the webapi (SYNO.API.Auth) and ransomware campaigns. Serves the recognizable
-- DSM portal + captures webapi auth.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("account=([^&]*)") if u then meta("auth_user", u); flag("synology-login-attempt") end end
local p = string.lower(path)
flag("synology-access")
if p:find("/webapi/auth.cgi") or p:find("syno.api.auth") then flag("synology-webapi-probe") end
if p:find("/webapi/entry.cgi") then flag("synology-entry-probe") end
local html = "<html><head><title>Synology DiskStation</title></head><body><div id='sds-login'>DSM</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
