-- Fake Avaya Aura System Manager web UI (handler: lua, HTTP 443). Avaya Aura is
-- the enterprise UC management plane. Greets as Avaya, captures the login
-- attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("avaya_auth", (h:gsub("[\r\n]", "")))
    flag("avaya-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Avaya\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("avaya-access")
path = path or "/"
if path:find("/SMGR") or path:find("/network%-login") or path:find("/admin") then
  meta("avaya_path", path)
  flag("avaya-admin-access")
  send("401 Unauthorized", "<html><body>Authentication required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("avaya-login-attempt")
  send("200 OK", "<html><body>Invalid user ID or password</body></html>")
else
  send("200 OK", "<html><head><title>Avaya Aura System Manager</title></head><body>Avaya Aura</body></html>")
end
