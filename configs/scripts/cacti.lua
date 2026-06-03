-- Fake Cacti (handler: lua, HTTP). Network-graphing app with a history of
-- unauth SQLi / command injection (CVE-2022-46169, CVE-2023-39362). Captures
-- the login and flags remote_agent.php / poller probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nX-Powered-By: PHP/7.4.33\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("cacti-access")
local p = string.lower(path or "/")
if p:find("remote_agent%.php") then flag("cacti-remote-agent-probe") end  -- CVE-2022-46169
local u = body:match("login_username=([^&]*)"); local pw = body:match("login_password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("cacti-login-attempt") end
send("200 OK", "<html><head><title>Login to Cacti</title></head><body><form method=post><input name=login_username><input type=password name=login_password></form><div>Version 1.2.24</div></body></html>")
