-- Fake F5 BIG-IP TMUI / iControl REST (handler: lua, HTTP). BIG-IP is targeted
-- by CVE-2020-5902 (TMUI directory traversal RCE via /tmui/login.jsp/..;/) and
-- CVE-2022-1388 (iControl REST auth bypass on /mgmt/tm/util/bash with an
-- X-F5-Auth-Token / Connection header trick). Serves the recognizable BIG-IP
-- login + flags both exploit paths and captures auth.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("f5-auth-attempt") end
  if hl:find("^x%-f5%-auth%-token:") or (hl:find("^connection:") and h:lower():find("x%-f5%-auth%-token")) then
    flag("f5-cve-2022-1388-probe")
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("bash") and body:find("command") then flag("f5-cve-2022-1388-probe") end
end

local p = string.lower(path)
flag("f5-bigip-access")
if p:find("/tmui/login.jsp/..") or p:find("/hsqldb") then flag("f5-cve-2020-5902-probe") end
if p:find("/mgmt/tm/util/bash") then flag("f5-cve-2022-1388-probe") end
if p:find("/tmui/") then flag("f5-tmui-probe") end

local html = "<html><head><title>BIG-IP&reg;</title></head><body>" ..
  "<div class='logo'>F5 BIG-IP Configuration Utility</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: BigIP\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: BIGIPAuthCookie=" .. rng:hex(24) .. "; secure; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
