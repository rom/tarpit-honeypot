-- Fake Juniper Junos J-Web (handler: lua, HTTP). SRX/EX devices are exploited via
-- CVE-2023-36845 (PHPRC/external-variable injection on webauth_operation.php → RCE)
-- and the J-Web login is brute-forced. Serves the recognizable J-Web + flags it.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("auto_prepend_file") or b:find("phprc") then flag("junos-cve-2023-36845-probe") end end
local p = string.lower(path)
flag("junos-jweb-access")
if p:find("webauth_operation.php") then flag("junos-cve-2023-36845-probe") end
local html = "<html><head><title>Log In - Juniper Web Device Manager</title></head><body>Juniper Networks</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
