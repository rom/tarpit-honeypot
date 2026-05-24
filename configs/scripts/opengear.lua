-- Fake Opengear console-server web UI (handler: lua, HTTP 443). A console
-- server fronts the serial consoles of every device in the rack — a foothold
-- there is OOB access to all of them. Answers the Opengear login, captures the
-- attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("opengear_auth", (h:gsub("[\r\n]", "")))
    flag("opengear-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Opengear\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("opengear-access")
path = path or "/"
if path:find("/config") or path:find("/portmanager") or path:find("[Pp]ort") then
  meta("opengear_path", path)
  flag("opengear-console-access")
  send("401 Unauthorized", "<html><body>Login required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("opengear-login-attempt")
  send("200 OK", "<html><body>Invalid login</body></html>")
else
  send("200 OK", "<html><head><title>Opengear</title></head><body>Opengear Console Manager</body></html>")
end
