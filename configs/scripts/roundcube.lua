-- Fake Roundcube webmail (handler: lua, HTTP). A frequent target — CVE-2024-
-- 37383 stored XSS, the 2025 post-auth RCE, and constant credential stuffing.
-- Captures the login POST (_user/_pass) and the version probe. Nothing runs.
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
  local user = body:match("_user=([^&]*)")
  local pass = body:match("_pass=([^&]*)")
  if user then meta("roundcube_user", user) end
  if pass then meta("roundcube_pass", pass) end
  if user or pass then flag("roundcube-login-attempt") end
end
local ver = rng:choice({ "1.6.6", "1.5.7", "1.6.1", "1.4.15" })
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: nginx\r\n")
  conn:write("Set-Cookie: roundcube_sessid=" .. rng:hex(13) .. "; path=/; HttpOnly\r\n")
  conn:write("Content-Type: text/html; charset=UTF-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end
flag("roundcube-access")
path = path or "/"
if string.lower(path):find("[%?&]_task=settings") or string.lower(path):find("install") then
  flag("roundcube-admin-probe")
end
send("200 OK", "<html><head><title>Roundcube Webmail</title>" ..
  "<meta name='generator' content='Roundcube Webmail " .. ver .. "'></head><body>" ..
  "<form name='form' method='post'><input name='_user'><input type='password' name='_pass'>" ..
  "</form></body></html>")
