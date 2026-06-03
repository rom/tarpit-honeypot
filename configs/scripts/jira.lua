-- Fake Atlassian Jira (handler: lua, HTTP). Captures the dashboard login and
-- flags the SSRF / template-injection probe paths.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, ctype, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Atlassian Jira\r\nContent-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("jira-access")
local p = string.lower(path or "/")
if p:find("/secure/contactadministrators!default.jspa") then flag("jira-ssti-probe")  -- CVE-2019-11581
elseif p:find("/rest/api/2/dashboard/items/properties") then flag("jira-ssrf-probe") end -- CVE-2019-8451
local u = body:match("os_username=([^&]*)"); local pw = body:match("os_password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("jira-login-attempt") end
send("200 OK", "text/html", "<html><head><title>Log in - Jira</title></head><body><form action=/login.jsp method=post><input name=os_username><input type=password name=os_password></form></body></html>")
