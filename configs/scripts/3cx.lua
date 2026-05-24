-- Fake 3CX management console (handler: lua, HTTP 5001/443). 3CX is a widely
-- deployed IP-PBX (the 2023 supply-chain compromise put it on every radar). Greets
-- as the 3CX console, captures the login attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("tcx_auth", (h:gsub("[\r\n]", "")))
    flag("3cx-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: 3CX\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("3cx-access")
path = path or "/"
if path:find("/api/login") or method == "POST" then
  flag("3cx-login-attempt")
  send("401 Unauthorized", "application/json", '{"Status":"AuthError"}')
elseif path:find("/api/") or path:find("/management") then
  meta("tcx_path", path)
  flag("3cx-admin-access")
  send("401 Unauthorized", "application/json", '{"Status":"Unauthorized"}')
else
  send("200 OK", "text/html", "<html><head><title>3CX</title></head><body>3CX Phone System Management Console</body></html>")
end
