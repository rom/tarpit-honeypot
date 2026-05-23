-- Fake Portainer (handler: lua, HTTP 9443/9000). Portainer manages Docker /
-- Kubernetes; an unauth or default-admin instance is full container
-- takeover. Serves /api/status and captures auth attempts + endpoint probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)"); if n then clen = tonumber(n) end
end
if clen > 0 and clen < 8192 then meta("auth_body", conn:read(clen) or "") end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("portainer-access")
path = path or "/"
if path:find("^/api/status") then
  send("200 OK", '{"Version":"2.20.3","InstanceID":"' .. rng:hex(8) .. '"}')
elseif path:find("^/api/endpoints") then
  flag("portainer-endpoint-access")
  send("401 Unauthorized", '{"message":"Unauthorized","details":"Invalid JWT token"}')
elseif method == "POST" and path:find("/api/auth") then
  flag("portainer-login-attempt")
  send("422 Unprocessable Entity", '{"message":"Invalid credentials"}')
else
  send("200 OK", '{"status":"ok"}')
end
