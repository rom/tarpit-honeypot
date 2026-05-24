-- Fake Supermicro BMC / IPMI web UI (handler: lua, HTTP 80/443). An exposed
-- Supermicro BMC is full out-of-band control of the server (and has had auth-
-- bypass CVEs). Greets as the ATEN/Supermicro web server, captures the login
-- attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") or string.lower(h):find("^cookie:.*sid") then
    meta("bmc_auth", (h:gsub("[\r\n]", "")))
    flag("bmc-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Supermicro\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("supermicro-bmc-access")
path = path or "/"
if path:find("cgi/") or path:find("rpc/") or path:find("ipmi") then
  meta("bmc_path", path)
  flag("bmc-mgmt-access")
  send("401 Unauthorized", "<html><body>Authentication failed</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("bmc-login-attempt")
  send("200 OK", "<html><body>Invalid Username or Password</body></html>")
else
  send("200 OK", "<html><head><title>BMC</title></head><body>Supermicro IPMI</body></html>")
end
