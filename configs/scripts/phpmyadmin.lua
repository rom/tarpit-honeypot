-- Fake phpMyAdmin (handler: lua, HTTP). phpMyAdmin is one of the most
-- scanned web apps on the internet (setup scripts, SQLi, deserialization
-- CVEs). Serves a believable login page, captures the probed path + any
-- login POST + the pma_username/pma_password fields. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then
    clen = tonumber((h:match(":%s*(%d+)"))) or 0
  end
  if hl:find("^authorization:") then
    meta("pma_auth", (h:gsub("[\r\n]", "")))
    flag("phpmyadmin-auth-attempt")
  end
end

-- Read a bounded request body (login form), capture credentials.
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  local user = body:match("pma_username=([^&]*)") or body:match("pma_user=([^&]*)")
  local pass = body:match("pma_password=([^&]*)") or body:match("pma_pass=([^&]*)")
  if user then meta("pma_username", user) end
  if pass then meta("pma_password", pass) end
  if user or pass then flag("phpmyadmin-login-attempt") end
end

local ver = rng:choice({ "5.2.1", "5.2.0", "5.1.3", "4.9.7" })
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache/2.4.57 (Debian)\r\n")
  conn:write("X-ob_mode: 1\r\nSet-Cookie: phpMyAdmin=" .. rng:hex(13) .. "; path=/; HttpOnly\r\n")
  conn:write("Content-Type: text/html; charset=utf-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("phpmyadmin-access")
path = path or "/"
local p = string.lower(path)
if p:find("/setup") or p:find("scripts/setup.php") then
  flag("phpmyadmin-setup-probe")
  send("200 OK", "<html><title>phpMyAdmin setup</title><body>phpMyAdmin " .. ver .. " setup</body></html>")
elseif p:find("import_status") or p:find("sql.php") or p:find("%%27") or p:find("union") then
  flag("phpmyadmin-sqli-probe")
  send("200 OK", "<html><body>phpMyAdmin</body></html>")
else
  send("200 OK", "<html><head><title>phpMyAdmin</title></head><body>" ..
    "<h1>Welcome to phpMyAdmin " .. ver .. "</h1>" ..
    "<form method='post' action='index.php'>" ..
    "<input name='pma_username'><input type='password' name='pma_password'>" ..
    "<input type='submit' value='Go'></form></body></html>")
end
