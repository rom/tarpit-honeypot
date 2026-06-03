-- Fake Kong API Gateway Admin API (handler: lua, HTTP). An exposed Kong Admin API
-- (8001) lets an attacker add routes/plugins (incl. serverless functions → RCE).
-- Serves the recognizable Kong JSON + flags admin endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("pre%-function") or b:find("post%-function") or b:find("serverless") then flag("kong-serverless-rce-probe") end end
local p = string.lower(path)
flag("kong-admin-access")
if p:find("/services") or p:find("/routes") or p:find("/plugins") or p:find("/consumers") then flag("kong-admin-api-probe") end
local body = '{"tagline":"Welcome to kong","version":"3.4.2"}'
conn:write("HTTP/1.1 200 OK\r\nServer: kong/3.4.2\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
