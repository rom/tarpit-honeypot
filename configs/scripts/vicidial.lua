-- Fake VICIdial call-center dialer (handler: lua, HTTP 80/443). VICIdial is an
-- Asterisk-based contact-center suite with a long history of auth-bypass / SQLi /
-- RCE CVEs and is heavily mass-scanned. Greets as VICIdial, captures the login
-- attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("vicidial_auth", (h:gsub("[\r\n]", "")))
    flag("vicidial-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("vicidial-access")
path = path or "/"
if path:find("/agc/") or path:find("/vicidial/") then
  meta("vicidial_path", path)
  flag("vicidial-admin-access")
  send("200 OK", "<html><body>Account is not active</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("vicidial-login-attempt")
  send("200 OK", "<html><body>Invalid Username/Password</body></html>")
else
  send("200 OK", "<html><head><title>VICIDIAL</title></head><body>VICIdial Call Center Suite</body></html>")
end
