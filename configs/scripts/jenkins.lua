-- Fake Jenkins (handler: lua, HTTP 8080). An exposed Jenkins is remote code
-- execution via the Groovy /script console and a deep CVE tail. Greets with
-- the X-Jenkins header, captures the probed path + any script-console hit and
-- login attempts. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("jenkins_auth", (h:gsub("[\r\n]", "")))
    flag("jenkins-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Jetty(10.0.20)\r\nX-Jenkins: 2.452.1\r\n")
  conn:write("Content-Type: text/html;charset=utf-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end
flag("jenkins-access")
path = path or "/"
if path:find("^/script") or path:find("^/scriptText") then
  flag("jenkins-script-console")
  send("403 Forbidden", "<html><body>Authentication required</body></html>")
elseif path:find("^/api") then
  meta("jenkins_path", path)
  send("403 Forbidden", "<html><body>Forbidden</body></html>")
elseif path:find("^/login") or method == "POST" then
  flag("jenkins-login-attempt")
  send("401 Unauthorized", "<html><body>Invalid login</body></html>")
else
  send("200 OK", "<html><head><title>Dashboard [Jenkins]</title></head><body>Welcome to Jenkins!</body></html>")
end
