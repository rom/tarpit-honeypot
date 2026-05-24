-- Fake Oracle/Sun ILOM web UI (handler: lua, HTTP 443). Integrated Lights Out
-- Manager is out-of-band control of Sun/Oracle servers. Answers the ILOM login
-- page / Redfish root, captures the login attempt and probed path. Nothing
-- real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("ilom_auth", (h:gsub("[\r\n]", "")))
    flag("ilom-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Oracle ILOM\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("ilom-access")
path = path or "/"
if path:find("^/redfish") then
  meta("ilom_path", path)
  flag("ilom-mgmt-access")
  send("401 Unauthorized", "application/json", '{"error":{"code":"Base.1.0.GeneralError"}}')
elseif path:find("/iPages") or method == "POST" or path:find("[Ll]ogin") then
  flag("ilom-login-attempt")
  send("200 OK", "text/html", "<html><body>Authentication Failed</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Oracle ILOM</title></head><body>Integrated Lights Out Manager</body></html>")
end
