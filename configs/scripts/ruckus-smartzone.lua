-- Fake Ruckus SmartZone / vSZ controller (handler: lua, HTTP). Ruckus wireless
-- controllers are exploited via CVE-2023-32171 (RCE) and the web UI/API are
-- brute-forced. Serves the recognizable Ruckus UI + flags the API.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end end
local p = string.lower(path)
flag("ruckus-access")
if p:find("/wsg/api/") or p:find("/admin/") then flag("ruckus-api-probe") end
local html = "<html><head><title>Ruckus SmartZone</title></head><body>Ruckus Wireless</body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
