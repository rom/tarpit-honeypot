-- Fake Apache Superset (handler: lua, HTTP 8088). Exposed Superset instances
-- with the shipped default SECRET_KEY (CVE-2023-27524) let an attacker forge a
-- session cookie and reach admin / SQLLab RCE. Serves the login page, captures
-- login POSTs and forged-cookie / SQLLab probes. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen, hasSessionCookie = 0, false
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^cookie:") and hl:find("session=") then hasSessionCookie = true end
end
if hasSessionCookie then flag("superset-session-cookie") end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  local user = body:match("username=([^&]*)")
  if user then
    meta("superset_username", user)
    flag("superset-login-attempt")
  end
  if body:find('"sql"') or body:lower():find("select%s") then flag("superset-sqllab-query") end
end

local ver = rng:choice({ "2.1.0", "2.1.1", "3.0.1", "2.0.1" })
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Werkzeug/2.3.6 Python/3.9.18\r\n")
  conn:write("Set-Cookie: session=" .. rng:hex(20) .. "; HttpOnly; Path=/\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("superset-access")
path = path or "/"
local p = string.lower(path)
if p:find("/api/v1/") then
  flag("superset-api-probe")
  send("401 Unauthorized", "application/json", '{"msg":"Missing Authorization Header"}')
elseif p:find("/sqllab") then
  flag("superset-sqllab-access")
  send("302 Found", "text/html", "")
else
  send("200 OK", "text/html", "<html><head><title>Superset</title>" ..
    "<meta name='version' content='" .. ver .. "'></head><body>" ..
    "<form action='/login/' method='post'><input name='username'>" ..
    "<input type='password' name='password'></form></body></html>")
end
