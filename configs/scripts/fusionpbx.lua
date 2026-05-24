-- Fake FusionPBX admin (handler: lua, HTTP 443/80). FusionPBX is the FreeSWITCH
-- web GUI (with a history of auth-bypass / RCE CVEs). Greets as FusionPBX,
-- captures the login attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("fusionpbx_auth", (h:gsub("[\r\n]", "")))
    flag("fusionpbx-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("fusionpbx-access")
path = path or "/"
if path:find("/core/") or path:find("/app/") then
  meta("fusionpbx_path", path)
  flag("fusionpbx-admin-access")
  send("403 Forbidden", "<html><body>Access denied</body></html>")
elseif path:find("/login") or method == "POST" then
  flag("fusionpbx-login-attempt")
  send("200 OK", "<html><body>Username or Password incorrect</body></html>")
else
  send("200 OK", "<html><head><title>FusionPBX</title></head><body>FusionPBX</body></html>")
end
