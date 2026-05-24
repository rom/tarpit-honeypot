-- Fake Poly/Polycom VVX IP-phone web UI (handler: lua, HTTP 80/443). Like other
-- exposed IP phones it leaks SIP line credentials and can be re-provisioned.
-- Greets as the Polycom phone web, captures the login attempt and probed path.
-- Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("polycom_auth", (h:gsub("[\r\n]", "")))
    flag("polycom-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Polycom\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("polycom-access")
path = path or "/"
if path:find("/form-submit") or path:find("[Ss]etting") or path:find("[Ll]ine") then
  meta("polycom_path", path)
  flag("polycom-config-access")
  send("403 Forbidden", "<html><body>Forbidden</body></html>")
elseif method == "POST" or path:find("[Aa]uth") then
  flag("polycom-login-attempt")
  send("403 Forbidden", "<html><body>Invalid credentials</body></html>")
else
  send("200 OK", "<html><head><title>Polycom VVX</title></head><body>Poly VVX Business IP Phone</body></html>")
end
