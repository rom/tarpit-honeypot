-- Fake Apache Guacamole (handler: lua, HTTP 8080). Guacamole is a clientless
-- RDP/VNC/SSH gateway — a foothold there reaches every backend it brokers.
-- Answers the Guacamole API/login, captures the auth attempt and probed path.
-- Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^guacamole%-token:") or string.lower(h):find("^authorization:") then
    meta("guac_token", (h:gsub("[\r\n]", "")))
    flag("guacamole-token-presented")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("guacamole-access")
path = path or "/"
if path:find("/api/tokens") or method == "POST" then
  flag("guacamole-login-attempt")
  send("403 Forbidden", "application/json", '{"message":"Invalid login","type":"INVALID_CREDENTIALS"}')
elseif path:find("/api/") then
  meta("guac_path", path)
  flag("guacamole-api-access")
  send("403 Forbidden", "application/json", '{"message":"Permission denied"}')
else
  send("200 OK", "text/html", "<html><head><title>Apache Guacamole</title></head><body>Guacamole</body></html>")
end
