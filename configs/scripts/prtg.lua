-- Fake PRTG Network Monitor (handler: lua, HTTP). PRTG is brute-forced
-- (prtgadmin) and probed for CVE-2018-9276 (authenticated parameter command
-- injection in the notification system). Serves the recognizable PRTG login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end end
local p = string.lower(path)
flag("prtg-access")
if p:find("/public/checklogin.htm") then flag("prtg-login-probe") end
if p:find("/api/") and (p:find("addurl") or p:find("editsettings")) then flag("prtg-cve-2018-9276-probe") end
local ver = rng:choice({ "23.4.90.1399", "22.1.74.1869", "20.1.56.1574" })
meta("prtg_version", ver)
local html = "<html><head><title>Welcome | PRTG Network Monitor (" .. ver .. ")</title></head><body>PRTG</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: PRTG/" .. ver .. "\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
