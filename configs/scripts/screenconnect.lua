-- Fake ConnectWise ScreenConnect / Control (handler: lua, HTTP 8040). A remote-
-- support server whose auth-bypass (CVE-2024-1709) was mass-exploited; a foothold
-- pushes an agent to every managed endpoint. Answers the host page / login,
-- captures the attempt and probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("sc_auth", (h:gsub("[\r\n]", "")))
    flag("screenconnect-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: ScreenConnect\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("screenconnect-access")
path = path or "/"
-- The CVE-2024-1709 setup-wizard path is a high-signal probe.
if path:lower():find("setupwizard") then
  meta("sc_path", path)
  flag("screenconnect-setup-bypass")
  send("200 OK", "text/html", "<html><body>Setup Wizard</body></html>")
elseif path:find("/Services/") or method == "POST" or path:find("[Ll]ogin") then
  flag("screenconnect-login-attempt")
  send("200 OK", "application/json", '{"success":false}')
else
  send("200 OK", "text/html", "<html><head><title>ScreenConnect</title></head><body>ConnectWise Control</body></html>")
end
