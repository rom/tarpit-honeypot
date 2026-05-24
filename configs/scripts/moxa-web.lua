-- Fake Moxa device web console (handler: lua, HTTP 80). Moxa serial device
-- servers / managed switches sit at the IT/OT edge and have had auth-bypass
-- and command-injection CVEs. Answers the device console, captures the login
-- attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("moxa_auth", (h:gsub("[\r\n]", "")))
    flag("moxa-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: MoxaHttp/1.0\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("moxa-access")
path = path or "/"
if path:find("/Config") or path:find("/Net") or path:find("%.asp") then
  meta("moxa_path", path)
  flag("moxa-config-access")
  send("401 Unauthorized", "<html><body>Please login</body></html>")
elseif path:find("/forms") or method == "POST" then
  flag("moxa-login-attempt")
  send("401 Unauthorized", "<html><body>Wrong password</body></html>")
else
  send("200 OK", "<html><head><title>Moxa</title></head><body>Moxa Device Server</body></html>")
end
