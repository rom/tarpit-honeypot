-- Fake Proxmox VE (handler: lua, HTTPS 8006). Virtualization manager; its API
-- ticket endpoint is a credential-capture goldmine. Captures the
-- /api2/json/access/ticket login POST.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, ctype, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: pve-api-daemon/3.0\r\nContent-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("proxmox-access")
local p = string.lower(path or "/")
if p:find("/api2/json/access/ticket") then
  local u = body:match("username=([^&]*)"); local pw = body:match("password=([^&]*)")
  if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
  flag("proxmox-login-attempt")
  send("401 No ticket", "application/json", '{"data":null}')
else
  send("200 OK", "text/html", "<html><head><title>Proxmox Virtual Environment</title></head><body>Proxmox VE 8.1</body></html>")
end
