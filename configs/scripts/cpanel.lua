-- Fake cPanel / WHM (handler: lua, HTTP). The hosting control panel (2082-2087)
-- is mass-brute-forced and probed. Serves the recognizable cPanel login + captures
-- creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("user=([^&]*)") if u then meta("auth_user", u); flag("cpanel-login-attempt") end end
local p = string.lower(path)
flag("cpanel-access")
if p:find("/login/") or p:find("/cpsess") then flag("cpanel-login-probe") end
local html = "<html><head><title>cPanel Login</title></head><body>cPanel</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: cpsrvd/11.110\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
