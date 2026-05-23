-- Fake Harbor container registry (handler: lua, HTTP 80/443). Harbor hosts
-- private images and has had auth-bypass CVEs (CVE-2022-46463). Serves the
-- systeminfo API and captures login / catalog probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)"); if n then clen = tonumber(n) end
end
if clen > 0 and clen < 8192 then meta("login_body", conn:read(clen) or "") end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("harbor-access")
path = path or "/"
if path:find("^/api/v2.0/systeminfo") then
  send("200 OK", '{"harbor_version":"v2.10.2","auth_mode":"db_auth","registry_url":"harbor.local"}')
elseif path:find("^/v2/_catalog") or path:find("^/api/v2.0/projects") then
  flag("harbor-catalog-access")
  send("401 Unauthorized", '{"errors":[{"code":"UNAUTHORIZED"}]}')
elseif method == "POST" and path:find("/c/login") then
  flag("harbor-login-attempt")
  send("401 Unauthorized", '{"errors":[{"code":"UNAUTHORIZED"}]}')
else
  send("200 OK", '{"status":"ok"}')
end
