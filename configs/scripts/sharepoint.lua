-- Fake Microsoft SharePoint (handler: lua, HTTP). Captures the _forms login and
-- flags the ToolPane / deserialization RCE probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 16384 then clen = 16384 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Microsoft-IIS/10.0\r\nX-SharePointHealthScore: 0\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("sharepoint-access")
local p = string.lower(path or "/")
if p:find("/_layouts/15/toolpane.aspx") then flag("sharepoint-toolpane-rce-probe")  -- CVE-2025-53770 / ToolShell class
elseif p:find("/_vti_bin/") then flag("sharepoint-vti-probe") end
local u = body:match("UserName=([^&]*)") or body:match("ctl00%$.-UserName=([^&]*)")
local pw = body:match("Password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("sharepoint-login-attempt") end
send("200 OK", "<html><head><title>Sign In</title></head><body><form action=/_forms/default.aspx method=post><input name=UserName><input type=password name=Password></form></body></html>")
