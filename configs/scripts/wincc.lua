-- Fake Siemens SIMATIC WinCC / WebNavigator (handler: lua, HTTP 80). An exposed
-- WinCC HMI exposes the plant SCADA screens and has a long CVE history. Greets
-- as the SIMATIC web server, captures the login attempt and probed path.
-- Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("wincc_auth", (h:gsub("[\r\n]", "")))
    flag("wincc-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: SIMATIC WinCC\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("wincc-access")
path = path or "/"
if path:find("/WebNavigator") or path:find("/Diagnose") then
  meta("wincc_path", path)
  flag("wincc-scada-access")
  send("401 Unauthorized", "<html><body>WinCC: authentication required</body></html>")
elseif path:find("/login") or method == "POST" then
  flag("wincc-login-attempt")
  send("401 Unauthorized", "<html><body>Logon failed</body></html>")
else
  send("200 OK", "<html><head><title>SIMATIC WinCC</title></head><body>Siemens SIMATIC HMI</body></html>")
end
