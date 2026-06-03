-- Fake JetBrains TeamCity (handler: lua, HTTP 8111). CI servers hold deploy
-- creds; CVE-2024-27198 auth bypass (a ;.jsp alternate path) is mass-scanned.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("http-auth-attempt") end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, ctype, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: TeamCity\r\nContent-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("teamcity-access")
local p = path or "/"
if p:find(";%.jsp") or p:lower():find("/app/rest/users.*;") then flag("teamcity-cve-2024-27198-probe") end
if p:lower():find("/app/rest/server") then flag("teamcity-rest-probe") end
local u = body:match("username=([^&]*)"); local pw = body:match("password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("teamcity-login-attempt") end
send("200 OK", "text/html", "<html><head><title>Log in to TeamCity</title></head><body><form action=/loginSubmit.html method=post><input name=username><input type=password name=password></form><div>TeamCity 2023.11</div></body></html>")
