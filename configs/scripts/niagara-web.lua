-- Fake Tridium Niagara station web UI (handler: lua, HTTP 80/443). Niagara
-- (Honeywell/JCI building automation) drives HVAC/energy across large estates
-- and has had platform CVEs. Answers the station login, captures the attempt
-- and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") or string.lower(h):find("^cookie:.*niagara") then
    meta("niagara_auth", (h:gsub("[\r\n]", "")))
    flag("niagara-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Niagara Web Server/1.1\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("niagara-access")
path = path or "/"
if path:find("^/prelogin") or path:find("^/login") or method == "POST" then
  flag("niagara-login-attempt")
  send("401 Unauthorized", "<html><body>Invalid login</body></html>")
elseif path:find("^/ord") or path:find("station") then
  meta("niagara_path", path)
  flag("niagara-station-access")
  send("403 Forbidden", "<html><body>Forbidden</body></html>")
else
  send("200 OK", "<html><head><title>Niagara</title></head><body>Tridium Niagara Station</body></html>")
end
