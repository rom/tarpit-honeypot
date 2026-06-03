-- Fake Webmin (handler: lua, HTTPS 10000). A perennial RCE target
-- (CVE-2019-15107 password-change RCE). Captures the login POST + Authorization
-- and flags the password_change.cgi probe. Nothing executes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("http-auth-attempt") end
end
local body = ""
if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: MiniServ/1.981\r\nContent-Type: text/html\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("webmin-access")
path = path or "/"
local p = string.lower(path)
if p:find("password_change%.cgi") then
  flag("webmin-passwd-rce-probe")  -- CVE-2019-15107
  meta("webmin_pam", body)
end
local u = body:match("user=([^&]*)"); local pw = body:match("pass=([^&]*)")
if u then meta("auth_user", u) end
if pw then meta("auth_pass", pw) end
if u or pw then flag("webmin-login-attempt") end
send("200 OK", "<html><head><title>Login to Webmin</title></head><body><h1>Login to Webmin</h1><form action=/session_login.cgi method=post><input name=user><input type=password name=pass><input type=submit value=Login></form></body></html>")
