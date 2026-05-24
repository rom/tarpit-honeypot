-- Fake Issabel / Elastix PBX web UI (handler: lua, HTTP 80/443). Issabel (the
-- Elastix successor) is an Asterisk distro whose web UI has had command-injection
-- CVEs. Greets as Issabel, captures the login attempt and probed path. Nothing
-- real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("issabel_auth", (h:gsub("[\r\n]", "")))
    flag("issabel-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("issabel-access")
path = path or "/"
if path:find("/index.php") or path:find("/modules/") then
  meta("issabel_path", path)
  flag("issabel-admin-access")
  send("403 Forbidden", "<html><body>Access denied</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("issabel-login-attempt")
  send("200 OK", "<html><body>Login incorrect</body></html>")
else
  send("200 OK", "<html><head><title>Issabel</title></head><body>Issabel PBX</body></html>")
end
