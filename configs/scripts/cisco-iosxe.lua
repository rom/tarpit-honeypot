-- Fake Cisco IOS XE Web UI (handler: lua, HTTP). The IOS XE web management UI
-- was mass-implanted in 2023 via CVE-2023-20198 (unauth account creation on the
-- /webui endpoints) chained with CVE-2023-20273 (privilege escalation). Serves
-- the recognizable IOS XE login + flags the webui_wsma / implant paths.
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
  -- The implant talks to webui_wsma_http(s) with an Oec/menu payload.
  if body:find("Oec") or body:find("aaa") then flag("cisco-iosxe-implant-probe") end
end

local p = string.lower(path)
flag("cisco-iosxe-access")
if p:find("/webui/") or p:find("/webui_wsma") then flag("cisco-cve-2023-20198-probe") end
if p:find("%%25") or p:find("/%%2577") then flag("cisco-iosxe-implant-probe") end

local html = "<html><head><title>Cisco</title></head><body>" ..
  "<div id='login'>Cisco IOS XE Web User Interface</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: admin_auth_token=" .. rng:hex(20) .. "; path=/; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
