-- Fake solar-inverter web portal (handler: lua, HTTP 80). Internet-exposed PV
-- inverters / data loggers (SMA, SolarEdge, Fronius) let an attacker read and
-- curtail generation. Answers the device dashboard, captures the login attempt
-- and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("solar_auth", (h:gsub("[\r\n]", "")))
    flag("solar-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: lighttpd\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("solar-inverter-access")
path = path or "/"
if path:find("dyn/getDashValues") or path:find("/solar_api") then
  meta("solar_path", path)
  flag("solar-data-access")
  send("200 OK", "application/json", '{"result":{"0199-xxxxx":{"6100_40263F00":{"1":[{"val":4200}]}}}}')
elseif path:find("dyn/login") or method == "POST" then
  flag("solar-login-attempt")
  send("200 OK", "application/json", '{"result":{"sid":null},"err":401}')
else
  send("200 OK", "text/html", "<html><head><title>Sunny WebBox</title></head><body>SMA Solar Technology</body></html>")
end
