-- Fake Laravel application (handler: lua, HTTP 80/8000). Two of the most-scanned
-- Laravel mistakes: a web-readable /.env (leaking APP_KEY + DB/mail/AWS creds)
-- and debug mode left on, where CVE-2021-3129 (Ignition execute-solution) is
-- unauthenticated RCE. Decoy only — the .env is fabricated honeytoken bait.

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

flag("laravel-probe")
meta("intent", "Laravel application probe")

if path:find("%.env") then
  flag("laravel-env-probe")
  meta("intent", "Laravel /.env secret-file access — credential harvesting")
  local env =
    "APP_NAME=Laravel\nAPP_ENV=production\nAPP_DEBUG=true\n" ..
    "APP_KEY=base64:" .. rng:hex(32) .. "\n" ..
    "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=app\n" ..
    "DB_USERNAME=laravel\nDB_PASSWORD=" .. rng:hex(8) .. "\n" ..
    "MAIL_HOST=smtp.mailtrap.io\nAWS_ACCESS_KEY_ID=AKIA" .. string.upper(rng:hex(8)) .. "\n"
  send("200 OK", "text/plain", env)
elseif path:find("/_ignition/execute%-solution") then
  flag("laravel-cve-2021-3129")
  meta("intent", "Laravel Ignition execute-solution (CVE-2021-3129) — unauthenticated RCE attempt")
  send("200 OK", "application/json", '{"file":"","line":0}')
elseif method == "POST" and path:find("login") then
  local u = body:match("email=([^&\r\n]+)") or body:match("username=([^&\r\n]+)")
  local p = body:match("password=([^&\r\n]+)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  send("302 Found", "text/html", "")
else
  send("200 OK", "text/html",
    "<html><head><title>Laravel</title></head><body><h1>Laravel</h1></body></html>")
end
