-- Fake phpIPAM (handler: lua, HTTP). IP-address management app, brute-forced and
-- probed for SQLi CVEs. Serves the recognizable login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("ipamusername=([^&]*)") if u then meta("auth_user", u); flag("phpipam-login-attempt") end end
local p = string.lower(path)
flag("phpipam-access")
if p:find("/api/") then flag("phpipam-api-probe") end
local html = "<html><head><title>phpipam</title></head><body>phpIPAM</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nSet-Cookie: phpipam=" .. rng:hex(26) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
