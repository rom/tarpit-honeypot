-- Fake NetBox (handler: lua, HTTP). DCIM/IPAM source of truth; an exposed
-- instance leaks the whole network inventory + secrets. Serves the recognizable
-- NetBox API + captures the token + login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:%s*token") then meta("netbox_token", (h:gsub("[\r\n]", ""))); flag("netbox-token-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("netbox-access")
if p:find("/api/dcim/") or p:find("/api/secrets/") or p:find("/api/ipam/") then flag("netbox-api-probe") end
local body = '{"dcim":"/api/dcim/","ipam":"/api/ipam/","secrets":"/api/secrets/"}'
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
