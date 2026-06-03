-- Fake Atlassian Bitbucket (handler: lua, HTTP). Bitbucket Data Center is hit by
-- CVE-2022-36804 (command injection via the archive API) and brute-forced.
-- Serves the recognizable Bitbucket UI + flags the archive endpoint.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("bitbucket-auth-attempt") end end
local p = string.lower(path)
flag("bitbucket-access")
if p:find("/rest/api/") and p:find("/archive") then flag("bitbucket-cve-2022-36804-probe") end
if p:find("/rest/api/1.0/") then flag("bitbucket-api-probe") end
local html = "<html><head><title>Log in - Bitbucket</title></head><body>Bitbucket</body></html>"
conn:write("HTTP/1.1 200 OK\r\nX-AREQUESTID: @" .. rng:hex(8) .. "\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
