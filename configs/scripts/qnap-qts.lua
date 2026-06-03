-- Fake QNAP QTS NAS (handler: lua, HTTP). QNAP NAS devices are mass-targeted by
-- ransomware (DeadBolt / Qlocker) via bugs like CVE-2022-27593 (externally-
-- controlled reference in Photo Station) and CVE-2021-28799, and brute-forced
-- on the QTS login. Serves the recognizable QTS login + flags the known paths
-- and captures the login POST.
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
  local body = conn:read(clen) or ""
  meta("post_body", body)
  local u = body:match("user=([^&]*)")
  local pw = body:match("pwd=([^&]*)") or body:match("password=([^&]*)")
  if u then meta("qnap_user", u) end
  if pw then meta("qnap_pass", pw) end
  if u or pw then flag("qnap-login-attempt") end
end

local p = string.lower(path)
flag("qnap-access")
if p:find("/photo/") or p:find("/cgi%-bin/filemanager") then flag("qnap-cve-2022-27593-probe") end
if p:find("/cgi%-bin/authlogin") then flag("qnap-login-probe") end

local html = "<html><head><title>QNAP Turbo NAS</title></head><body>" ..
  "<div id='qts'>Welcome to QTS</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: http server 1.3.0\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: NAS_SID=" .. rng:hex(16) .. "; path=/; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
