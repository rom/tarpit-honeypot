-- Fake Cockpit web console (handler: lua, HTTP 9090). Cockpit is the Linux
-- server management console (RHEL/Fedora) — a foothold there is root-level host
-- administration. Answers the Cockpit login, captures the attempt and probed
-- path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("cockpit_auth", (h:gsub("[\r\n]", "")))
    flag("cockpit-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Cockpit\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("cockpit-access")
path = path or "/"
if path:find("/cockpit/login") or method == "POST" then
  flag("cockpit-login-attempt")
  send("401 Authentication failed", "<html><body>Authentication failed</body></html>")
elseif path:find("/cockpit/") then
  meta("cockpit_path", path)
  flag("cockpit-console-access")
  send("401 Unauthorized", "<html><body>Not authorized</body></html>")
else
  send("200 OK", "<html><head><title>Cockpit</title></head><body>Loading...</body></html>")
end
