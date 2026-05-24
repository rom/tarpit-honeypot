-- Fake SEL protection-relay web UI (handler: lua, HTTP 80). Schweitzer (SEL)
-- relays protect the power grid; their web/HTTP interface exposes settings and
-- metering. Answers the relay home/settings, captures the login attempt and
-- probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("sel_auth", (h:gsub("[\r\n]", "")))
    flag("sel-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: SEL\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("sel-relay-access")
path = path or "/"
if path:find("[Ss]ettings") or path:find("[Mm]eter") then
  meta("sel_path", path)
  flag("sel-settings-access")
  send("401 Unauthorized", "<html><body>Access Level required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("sel-login-attempt")
  send("401 Unauthorized", "<html><body>Invalid password</body></html>")
else
  send("200 OK", "<html><head><title>SEL-751</title></head><body>SEL Feeder Protection Relay</body></html>")
end
