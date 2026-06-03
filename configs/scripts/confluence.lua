-- Fake Atlassian Confluence (handler: lua, HTTP). OGNL injection RCE central
-- (CVE-2021-26084, CVE-2022-26134, CVE-2023-22527). Flags the known templating
-- paths and captures the login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 16384 then clen = 16384 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Atlassian Confluence\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("confluence-access")
local p = string.lower(path or "/")
if p:find("/template/aui/text%-inline.vm") then flag("confluence-cve-2023-22527-probe")
elseif p:find("createpage%-entervariables.action") then flag("confluence-cve-2021-26084-probe")
elseif p:find("getstatesofcurrentuser") or p:find("queryjson") then flag("confluence-ognl-probe") end
if body:lower():find("ognl") or body:lower():find("@java.lang.runtime") or body:find("\\u0027") then flag("confluence-ognl-payload") end
local u = body:match("os_username=([^&]*)"); local pw = body:match("os_password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("confluence-login-attempt") end
send("200 OK", "<html><head><title>Log In - Confluence</title></head><body><form action=/dologin.action method=post><input name=os_username><input type=password name=os_password></form></body></html>")
