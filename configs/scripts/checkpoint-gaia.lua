-- Fake Check Point Quantum / GAiA portal (handler: lua, HTTP). Check Point
-- gateways are exploited via CVE-2024-24919 (information disclosure / arbitrary
-- file read on the Remote Access VPN portal via /clients/MIL path traversal).
-- Serves the recognizable GAiA portal + flags the traversal.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("aRequest=") and b:find("%.%.") then flag("checkpoint-cve-2024-24919-probe") end end
local p = string.lower(path)
flag("checkpoint-access")
if p:find("/clients/mil") then flag("checkpoint-cve-2024-24919-probe") end
local html = "<html><head><title>Check Point Mobile</title></head><body>Check Point Quantum Security Gateway</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Check Point SVN foundation\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
