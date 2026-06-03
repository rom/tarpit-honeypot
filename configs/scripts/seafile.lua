-- Fake Seafile (handler: lua, HTTP). Self-hosted file-sync; the seahub web UI and
-- API are brute-forced and probed. Serves the recognizable Seahub login +
-- captures the login POST.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("login=([^&]*)") or b:match("username=([^&]*)") if u then meta("auth_user", u); flag("seafile-login-attempt") end end
local p = string.lower(path)
flag("seafile-access")
if p:find("/api2/auth%-token") or p:find("/accounts/login") then flag("seafile-auth-probe") end
local html = "<html><head><title>Seafile</title></head><body><div id='log-in-panel'>Seafile</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nSet-Cookie: sessionid=" .. rng:hex(16) .. "; Path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
