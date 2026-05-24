-- Fake Cisco UCS CIMC web UI (handler: lua, HTTP 443). The Integrated
-- Management Controller is out-of-band control of Cisco UCS servers (with a
-- history of critical CVEs). Answers the CIMC login / XML-API, captures the
-- login attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("cimc_auth", (h:gsub("[\r\n]", "")))
    flag("cimc-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: CIMC\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("cimc-access")
path = path or "/"
if path:find("/nuova") or path:find("/redfish") then
  meta("cimc_path", path)
  flag("cimc-mgmt-access")
  send("401 Unauthorized", "application/xml", '<error response="yes" errorCode="551"/>')
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("cimc-login-attempt")
  send("200 OK", "text/html", "<html><body>Login Error</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Cisco Integrated Management Controller</title></head><body>Cisco UCS CIMC</body></html>")
end
