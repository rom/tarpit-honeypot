-- Fake SolarWinds Serv-U web client (handler: lua, HTTP). Serv-U is exploited via
-- CVE-2024-28995 (directory traversal arbitrary file read) and CVE-2021-35211
-- (memory-corruption RCE). Serves the recognizable Serv-U login + flags traversal.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end end
local p = string.lower(path)
flag("servu-access")
if (p:find("internaldir=") or p:find("/?")) and (p:find("%.%.") or p:find("%%2e%%2e")) then flag("servu-cve-2024-28995-probe") end
if p:find("/web client/") or p:find("/?internaldir") then flag("servu-webclient-probe") end
local html = "<html><head><title>Serv-U Web Client</title></head><body>Serv-U File Server</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Serv-U/15.4\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
