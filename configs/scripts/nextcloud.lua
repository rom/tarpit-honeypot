-- Fake Nextcloud (handler: lua, HTTP). Self-hosted file sync; captures the
-- login POST and the WebDAV/Authorization basic-auth attempts.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("http-auth-attempt") end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nX-Powered-By: PHP/8.2\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("nextcloud-access")
local u = body:match("user=([^&]*)"); local pw = body:match("password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("nextcloud-login-attempt") end
send("200 OK", "<html><head><title>Nextcloud</title></head><body><form method=post name=login><input name=user><input type=password name=password></form><div>Nextcloud Hub 8 (28.0.1)</div></body></html>")
