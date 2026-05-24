-- Fake Cisco Unified CM admin (handler: lua, HTTP 8443/443). CUCM is the
-- enterprise call-control plane; its admin / serviceability pages are a prime
-- target. Greets as CUCM, captures the login attempt and probed path. Nothing
-- real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("cucm_auth", (h:gsub("[\r\n]", "")))
    flag("cucm-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Cisco CUCM\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("cucm-access")
path = path or "/"
if path:find("/ccmadmin") or path:find("/cmplatform") or path:find("/ucmuser") then
  meta("cucm_path", path)
  flag("cucm-admin-access")
  send("401 Unauthorized", "<html><body>Authentication required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("cucm-login-attempt")
  send("200 OK", "<html><body>Authentication failed</body></html>")
else
  send("200 OK", "<html><head><title>Cisco Unified CM Administration</title></head><body>Cisco Unified Communications Manager</body></html>")
end
