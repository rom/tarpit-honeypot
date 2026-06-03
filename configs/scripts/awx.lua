-- Fake Ansible AWX / Tower (handler: lua, HTTP). An exposed AWX lets an attacker
-- run playbooks across the fleet. Serves the recognizable AWX API + captures the
-- bearer token + login JSON.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("awx-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("\"username\"%s*:%s*\"([^\"]*)") if u then meta("auth_user", u); flag("awx-login-attempt") end end
local p = string.lower(path)
flag("awx-access")
if p:find("/api/v2/job_templates") or p:find("/api/v2/tokens") then flag("awx-api-probe") end
local body = '{"description":"AWX REST API","current_version":"/api/v2/","available_versions":{"v2":"/api/v2/"}}'
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
