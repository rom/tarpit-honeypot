-- Fake Yealink IP-phone web UI (handler: lua, HTTP 80/443). Exposed IP phones
-- leak SIP credentials and can be re-provisioned for eavesdropping/toll fraud.
-- Greets as the Yealink phone web, captures the login attempt and probed path.
-- Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("yealink_auth", (h:gsub("[\r\n]", "")))
    flag("yealink-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Yealink\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("yealink-access")
path = path or "/"
if path:find("/servlet") or path:find("[Aa]ccount") or path:find("[Cc]onfig") then
  meta("yealink_path", path)
  flag("yealink-config-access")
  send("401 Unauthorized", "<html><body>Authorization required</body></html>")
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("yealink-login-attempt")
  send("200 OK", "<html><body>Wrong user name or password</body></html>")
else
  send("200 OK", "<html><head><title>Yealink SIP-T54W</title></head><body>Yealink IP Phone</body></html>")
end
