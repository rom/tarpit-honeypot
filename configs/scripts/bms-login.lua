-- Fake Building Management System login (handler: lua, HTTP 80). Generic BMS /
-- BAS controllers (HVAC, access control, lighting) are widely exposed and
-- default-credentialed. Answers a login page, captures the login attempt and
-- probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("bms_auth", (h:gsub("[\r\n]", "")))
    flag("bms-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("bms-access")
path = path or "/"
if method == "POST" or path:find("[Ll]ogin") then
  flag("bms-login-attempt")
  send("200 OK", "<html><body>Invalid user name or password</body></html>")
elseif path:find("[Aa]larm") or path:find("[Ss]chedule") or path:find("[Tt]rend") then
  meta("bms_path", path)
  flag("bms-control-access")
  send("302 Found", "")
else
  send("200 OK", "<html><head><title>Building Management System</title></head><body>BMS Login</body></html>")
end
