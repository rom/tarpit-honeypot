-- Fake DrayTek Vigor router web admin (handler: lua, HTTP 80/443). DrayTek
-- SOHO routers are mass-targeted: CVE-2024-41592 (GetCGI buffer overflow on
-- /cgi-bin/mainfunction.cgi) and CVE-2020-8515 (RCE via the same CGI), plus
-- credential brute force on the web login. Decoy only.

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
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: DrayTek\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("draytek-probe")
meta("intent", "DrayTek Vigor web admin probe")

if path:find("mainfunction%.cgi") then
  flag("draytek-cgi-probe")
  meta("intent", "DrayTek Vigor mainfunction.cgi access (CVE-2020-8515 / CVE-2024-41592 surface)")
  local both = path .. body
  if both:find("keyPath") or both:find("rtick") or both:find("|") then
    flag("draytek-cgi-injection")
    meta("intent", "DrayTek Vigor CGI command injection attempt")
  end
  send("200 OK", "text/html", "<html><body>cgi</body></html>")
elseif path:find("login") or method == "POST" then
  local u = body:match("username=([^&\r\n]+)") or body:match("user=([^&\r\n]+)")
  local p = body:match("password=([^&\r\n]+)") or body:match("pass=([^&\r\n]+)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  send("200 OK", "text/html",
    "<html><head><title>Vigor Login</title></head><body><form name='_loginform'></form></body></html>")
else
  send("200 OK", "text/html",
    "<html><head><title>Vigor Router</title></head><body>DrayTek Vigor</body></html>")
end
