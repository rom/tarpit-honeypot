-- Fake Rundeck (handler: lua, HTTP). Job-automation server; an exposed instance
-- runs commands on managed nodes. Serves the recognizable login + captures the
-- API token + login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^x%-rundeck%-auth%-token:") then meta("rundeck_token", (h:gsub("[\r\n]", ""))); flag("rundeck-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("j_username=([^&]*)") if u then meta("auth_user", u); flag("rundeck-login-attempt") end end
local p = string.lower(path)
flag("rundeck-access")
if p:find("/api/") and (p:find("/run/command") or p:find("/job/")) then flag("rundeck-job-exec-probe") end
local html = "<html><head><title>Rundeck - Login</title></head><body>Rundeck</body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Rundeck-API-Version: 47\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
