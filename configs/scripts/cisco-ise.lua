-- Fake Cisco Identity Services Engine (ISE) admin (handler: lua, HTTP). Cisco ISE
-- is hit by deserialization/file-upload RCEs (CVE-2024-20399 class) and the admin
-- portal is brute-forced. Serves the recognizable ISE login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("cisco-ise-login-attempt") end end
local p = string.lower(path)
flag("cisco-ise-access")
if p:find("/admin/login.jsp") then flag("cisco-ise-login-probe") end
if p:find("/ers/config/") then flag("cisco-ise-api-probe") end
local html = "<html><head><title>Identity Services Engine</title></head><body>Cisco ISE</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nSet-Cookie: APPSESSIONID=" .. rng:hex(24) .. "; Path=/admin; Secure\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
