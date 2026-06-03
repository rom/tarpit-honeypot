-- Fake Redmine (handler: lua, HTTP). Ruby-on-Rails project tracker, brute-forced
-- and probed for known SQLi/file-disclosure CVEs. Serves the recognizable login +
-- captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("redmine-login-attempt") end end
local p = string.lower(path)
flag("redmine-access")
if p:find("/login") or p:find("/issues") then flag("redmine-probe") end
local html = "<html><head><title>Redmine</title></head><body>Redmine</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: Phusion Passenger\r\nContent-Type: text/html\r\nSet-Cookie: _redmine_session=" .. rng:hex(26) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
