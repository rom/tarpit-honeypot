-- Fake FreePBX admin web UI (handler: lua, HTTP 80/443). An exposed FreePBX is
-- full PBX control + trunk credentials (and has had RCE CVEs). Greets as the
-- FreePBX admin, captures the login attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("freepbx_auth", (h:gsub("[\r\n]", "")))
    flag("freepbx-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("freepbx-access")
path = path or "/"
if path:find("/admin/config.php") or path:find("/admin/ajax.php") then
  meta("freepbx_path", path)
  flag("freepbx-admin-access")
  send("403 Forbidden", "<html><body>Access denied</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("freepbx-login-attempt")
  send("200 OK", "<html><body>Invalid login</body></html>")
else
  send("200 OK", "<html><head><title>FreePBX Administration</title></head><body>Sangoma FreePBX</body></html>")
end
