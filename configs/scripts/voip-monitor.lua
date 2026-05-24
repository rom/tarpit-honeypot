-- Fake VoIP monitoring web UI (handler: lua, HTTP 80/443). VoIPmonitor / Homer
-- capture-and-analysis portals expose recorded calls and SIP traffic — a rich
-- collection target. Greets as the monitor UI, captures the login attempt and
-- probed path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("voipmon_auth", (h:gsub("[\r\n]", "")))
    flag("voip-monitor-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("voip-monitor-access")
path = path or "/"
if path:find("/api/") or path:find("[Cc]all") or path:find("[Pp]cap") then
  meta("voipmon_path", path)
  flag("voip-monitor-data-access")
  send("401 Unauthorized", "application/json", '{"error":"unauthorized"}')
elseif method == "POST" or path:find("[Ll]ogin") then
  flag("voip-monitor-login-attempt")
  send("200 OK", "application/json", '{"status":"error","message":"bad login"}')
else
  send("200 OK", "text/html", "<html><head><title>VoIPmonitor</title></head><body>VoIPmonitor GUI</body></html>")
end
