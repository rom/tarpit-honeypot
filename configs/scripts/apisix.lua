-- Fake Apache APISIX admin (handler: lua, HTTP). Captures the login / signature probe and flags it.
-- Detection + deception only; nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local p = string.lower(path or "/")
flag("apisix-access")
if p:find("/apisix/admin") then flag("apisix-admin-api-probe") end
local u = body:match("[uU]sername=([^&]*)") or body:match('"user"%s*:%s*"([^"]*)"') or body:match("[uU]ser=([^&]*)") or body:match('"username"%s*:%s*"([^"]*)"')
local pw = body:match("[pP]assword=([^&]*)") or body:match('"password"%s*:%s*"([^"]*)"')
if u then meta("auth_user", u) end
if pw then meta("auth_pass", pw) end
if u or pw then flag("apisix-login-attempt") end
local resp = "<!doctype html><html><head><title>Apache APISIX</title></head><body><h1>Apache APISIX</h1></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: APISIX/3.2.0\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#resp) .. "\r\nConnection: close\r\n\r\n" .. resp)
