-- Fake Alibaba Nacos (handler: lua, HTTP 8848). Nacos is a service-config
-- registry with a well-known auth-bypass (CVE-2021-29441) that yields config
-- secrets and user creation. Answers the auth/users probe and captures the
-- path + login attempt. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("nacos_auth", (h:gsub("[\r\n]", "")))
    flag("nacos-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: nacos\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("nacos-access")
path = path or "/"
if path:find("/nacos/v1/auth/users") or path:find("/nacos/v1/cs/configs") then
  meta("nacos_path", path)
  flag("nacos-config-access")
  send("403 Forbidden", '{"status":403,"message":"403 Forbidden"}')
elseif path:find("/nacos/v1/console/health") or path:find("/nacos") then
  send("200 OK", '{"status":"UP"}')
else
  send("404 Not Found", '{"status":404}')
end
