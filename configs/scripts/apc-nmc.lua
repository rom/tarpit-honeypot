-- Fake APC Network Management Card web UI (handler: lua, HTTP 80/443). The NMC
-- manages UPS / rack PDUs — control of power to a rack. Answers the APC log-on
-- page, captures the login attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("apc_auth", (h:gsub("[\r\n]", "")))
    flag("apc-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: APC\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("apc-nmc-access")
path = path or "/"
if path:find("[Oo]utlet") or path:find("[Cc]ontrol") or path:find("/NMC") then
  meta("apc_path", path)
  flag("apc-power-control")
  send("403 Forbidden", "<html><body>Not authorized</body></html>")
elseif method == "POST" or path:find("[Ll]ogon") or path:find("[Ll]ogin") then
  flag("apc-login-attempt")
  send("200 OK", "<html><body>The credentials are not valid</body></html>")
else
  send("200 OK", "<html><head><title>APC | Log On</title></head><body>Schneider Electric APC</body></html>")
end
