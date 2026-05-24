-- Fake operator-panel HMI web (handler: lua, HTTP 80). Touch-panel HMIs
-- (Weintek, Pro-face, Delta) ship a small web server for remote monitoring and
-- are routinely exposed with default credentials. Answers the panel page,
-- captures the login attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("hmi_auth", (h:gsub("[\r\n]", "")))
    flag("hmi-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Boa/0.94\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("hmi-panel-access")
path = path or "/"
if path:find("cgi%-bin") or path:find("MonitorPage") or path:find("[Ww]eb[Vv]isu") then
  meta("hmi_path", path)
  flag("hmi-screen-access")
  send("401 Unauthorized", "<html><body>Login required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("hmi-login-attempt")
  send("200 OK", "<html><body>Password incorrect</body></html>")
else
  send("200 OK", "<html><head><title>HMI Panel</title></head><body>Operator Panel</body></html>")
end
