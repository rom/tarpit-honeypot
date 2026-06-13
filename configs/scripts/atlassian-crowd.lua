-- Fake Atlassian Crowd identity server (handler: lua, HTTP 8095). CVE-2019-11580
-- abuses the development "pdkinstall" plugin endpoint to upload a malicious
-- plugin (RCE); the admin console login is also brute-forced for SSO access.
-- Decoy only — no plugin is installed; the login + upload are captured.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body = ""
if clen > 0 and clen < 65536 then body = conn:read(clen) or "" end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("crowd-probe")
meta("intent", "Atlassian Crowd probe")

if path:find("pdkinstall") or path:find("uploadplugin") then
  flag("crowd-cve-2019-11580")
  meta("intent", "Atlassian Crowd pdkinstall plugin upload (CVE-2019-11580) — RCE attempt")
  send("200 OK", "application/json", '{"status":"OK"}')
elseif path:find("login") or method == "POST" then
  local u = body:match("j_username=([^&\r\n]+)") or body:match("username=([^&\r\n]+)")
  local p = body:match("j_password=([^&\r\n]+)") or body:match("password=([^&\r\n]+)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  send("200 OK", "text/html",
    "<html><head><title>Log in - Crowd</title></head><body><form id='login-form'></form></body></html>")
else
  send("200 OK", "text/html",
    "<html><head><title>Crowd</title></head><body>Atlassian Crowd</body></html>")
end
