-- Fake Apache NiFi (handler: lua, HTTP). NiFi flow-management UI is targeted for
-- unauthenticated access to the API/processors (a misconfig that yields RCE via
-- ExecuteProcess/ExecuteScript). Serves the recognizable NiFi UI + flags API probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end end
local p = string.lower(path)
flag("nifi-access")
if p:find("/nifi%-api/process%-groups") or p:find("/nifi%-api/processors") then flag("nifi-api-probe") end
if p:find("executescript") or p:find("executeprocess") then flag("nifi-rce-processor-probe") end
local html = "<html><head><title>NiFi</title></head><body><div id='nifi'>Apache NiFi</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Jetty(9.4.x)\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
