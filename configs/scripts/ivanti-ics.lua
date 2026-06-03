-- Fake Ivanti Connect Secure / Pulse Secure VPN (handler: lua, HTTP). The
-- /dana-na/ web portal is heavily targeted: CVE-2023-46805 (auth bypass) +
-- CVE-2024-21887 (command injection via /api/v1/totp/user-backup-code and
-- license endpoints) were chained for mass exploitation. Serves the
-- recognizable Pulse portal + flags the known endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  meta("post_body", conn:read(clen) or "")
end

local p = string.lower(path)
flag("ivanti-ics-access")
if p:find("/api/v1/totp/user%-backup%-code") or p:find("/api/v1/license") then
  flag("ivanti-cve-2024-21887-probe")
end
if p:find("/dana%-na/auth") or p:find("/dana%-na/../") then flag("ivanti-cve-2023-46805-probe") end
if p:find("/dana%-na/") then flag("ivanti-portal-probe") end

local html = "<html><head><title>Pulse Secure</title></head><body>" ..
  "<div id='DSIDFormDataStr'>Welcome to the Ivanti Connect Secure portal</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html; charset=utf-8\r\n")
conn:write("Set-Cookie: DSID=" .. rng:hex(32) .. "; path=/; secure; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
