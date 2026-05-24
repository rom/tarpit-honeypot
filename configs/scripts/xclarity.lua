-- Fake Lenovo XClarity Controller (XCC) web UI (handler: lua, HTTP 443). XCC is
-- out-of-band control of Lenovo ThinkSystem servers. Answers the XCC login /
-- Redfish root, captures the login attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("xcc_auth", (h:gsub("[\r\n]", "")))
    flag("xcc-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: lighttpd\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("xcc-access")
path = path or "/"
if path:find("^/redfish") or path:find("/api/") then
  meta("xcc_path", path)
  flag("xcc-mgmt-access")
  send("401 Unauthorized", "application/json", '{"error":{"code":"Base.1.8.GeneralError"}}')
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("xcc-login-attempt")
  send("200 OK", "text/html", "<html><body>Login failed</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Lenovo XClarity Controller</title></head><body>Lenovo XCC</body></html>")
end
