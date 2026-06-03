-- Fake Apache Ambari (handler: lua, HTTP). Hadoop cluster manager; default
-- admin:admin and API access expose cluster control. Serves the Ambari login +
-- captures Basic auth + flags the API.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("ambari-auth-attempt") end end
local p = string.lower(path)
flag("ambari-access")
if p:find("/api/v1/clusters") or p:find("/api/v1/users") then flag("ambari-api-probe") end
local html = "<html><head><title>Ambari</title></head><body>Apache Ambari</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nUser: admin\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
