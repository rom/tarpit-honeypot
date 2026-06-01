-- Fake Adminer (handler: lua, HTTP). Adminer is a single-file DB front-end
-- with a history of SSRF / arbitrary-file-read CVEs (e.g. CVE-2021-43008
-- Elasticsearch/ClickHouse driver abuse). Serves the login form, captures the
-- chosen driver/server/username/password and any SSRF-shaped server value.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then
    clen = tonumber((h:match(":%s*(%d+)"))) or 0
  end
end

if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  -- Adminer posts auth[server]/auth[username]/... — browsers URL-encode the
  -- brackets (%5B/%5D), curl PoCs send them literally. Match both.
  local function field(k)
    return body:match("auth%[" .. k .. "%]=([^&]*)")
      or body:match("auth%%5B" .. k .. "%%5D=([^&]*)")
      or body:match("[?&]" .. k .. "=([^&]*)")
  end
  local driver = field("driver")
  local server = field("server")
  local user = field("username")
  local pass = field("password")
  if driver then meta("adminer_driver", driver) end
  if server then
    meta("adminer_server", server)
    -- An attacker pointing the "server" at an internal/cloud target is the
    -- SSRF primitive Adminer is abused for.
    if server:find("169.254") or server:find("localhost") or server:find("127.0.0") or server:find("metadata") then
      flag("adminer-ssrf-attempt")
    end
  end
  if user then meta("adminer_username", user) end
  if pass then meta("adminer_password", pass) end
  if user or pass then flag("adminer-login-attempt") end
end

local ver = rng:choice({ "4.8.1", "4.8.4", "5.0.5" })
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: nginx\r\n")
  conn:write("Content-Type: text/html; charset=utf-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("adminer-access")
send("200 OK", "<html><head><title>Login - Adminer</title></head><body>" ..
  "<h1>Adminer " .. ver .. "</h1><form method='post'>" ..
  "<select name='auth[driver]'><option value='server'>MySQL</option>" ..
  "<option value='pgsql'>PostgreSQL</option></select>" ..
  "<input name='auth[server]'><input name='auth[username]'>" ..
  "<input type='password' name='auth[password]'>" ..
  "<input type='submit' value='Login'></form></body></html>")
