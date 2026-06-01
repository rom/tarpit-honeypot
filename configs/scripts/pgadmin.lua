-- Fake pgAdmin 4 (handler: lua, HTTP). Web front-end for PostgreSQL; exposed
-- instances are targeted for credential theft + CVE-2023-5002/2024-3116 path
-- traversal / RCE. Captures the login POST and version/traversal probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  local user = body:match("email=([^&]*)")
  if user then
    meta("pgadmin_user", user)
    flag("pgadmin-login-attempt")
  end
end
local ver = rng:choice({ "8.4", "7.8", "8.6", "6.21" })
local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Werkzeug/3.0.1 Python/3.11\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b))
  conn:write("\r\nConnection: close\r\n\r\n" .. b)
end
flag("pgadmin-access")
path = path or "/"
local p = string.lower(path)
if p:find("validate_binary_path") or p:find("%.%./") then
  flag("pgadmin-traversal-probe")
  send("200 OK", "application/json", '{"success":0,"errormsg":"invalid path"}')
elseif p:find("/login") then
  send("200 OK", "text/html", "<html><title>pgAdmin 4</title><body><form method='post'><input name='email'>" ..
    "<input type='password' name='password'></form></body></html>")
else
  send("302 Found", "text/html", "")
end
