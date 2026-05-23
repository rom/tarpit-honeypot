-- Fake SonarQube (handler: lua, HTTP 9000). An exposed SonarQube leaks source,
-- quality data and often default admin:admin. Answers /api/system/status and
-- captures login attempts + the request path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("sonar_auth", (h:gsub("[\r\n]", "")))
    flag("sonarqube-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("sonarqube-access")
path = path or "/"
if path:find("^/api/system/status") then
  send("200 OK", '{"id":"AY1","version":"10.5.1.90531","status":"UP"}')
elseif path:find("^/api/authentication/login") or method == "POST" then
  flag("sonarqube-login-attempt")
  send("401 Unauthorized", '{"errors":[{"msg":"Authentication failed"}]}')
elseif path:find("^/api/") then
  meta("sonar_path", path)
  send("401 Unauthorized", '{"errors":[{"msg":"Insufficient privileges"}]}')
else
  send("200 OK", '{"message":"SonarQube"}')
end
