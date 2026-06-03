-- Fake Graylog (handler: lua, HTTP). Log-management UI/API, brute-forced and
-- probed; an exposed API token yields full log access. Serves the recognizable
-- Graylog API banner + captures the session/login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("graylog-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("\"username\"%s*:%s*\"([^\"]*)") if u then meta("auth_user", u); flag("graylog-login-attempt") end end
local p = string.lower(path)
flag("graylog-access")
if p:find("/api/system/sessions") or p:find("/api/cluster") then flag("graylog-api-probe") end
local body = '{"cluster_id":"' .. rng:hex(16) .. '","node_id":"' .. rng:hex(16) .. '","version":"5.2.0+abc"}'
conn:write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Graylog-Node-ID: " .. rng:hex(8) .. "\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
