-- Fake Inductive Automation Ignition SCADA gateway (handler: lua, HTTP 8088).
-- An exposed Ignition gateway is full plant control + project/tag data. Answers
-- the gateway status/info endpoint, captures the login attempt and the probed
-- path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("ignition_auth", (h:gsub("[\r\n]", "")))
    flag("ignition-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Ignition\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("ignition-access")
path = path or "/"
if path:find("^/StatusPing") or path:find("^/system/gwinfo") then
  send("200 OK", "application/json", '{"platformEdition":"standard","version":"8.1.37","state":"RUNNING"}')
elseif path:find("^/data/perspective") or path:find("^/main/") then
  meta("ignition_path", path)
  flag("ignition-project-access")
  send("403 Forbidden", "text/html", "<html><body>Access denied</body></html>")
elseif path:find("/login") or method == "POST" then
  flag("ignition-login-attempt")
  send("401 Unauthorized", "text/html", "<html><body>Invalid credentials</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Ignition Gateway</title></head><body>Inductive Automation Ignition</body></html>")
end
