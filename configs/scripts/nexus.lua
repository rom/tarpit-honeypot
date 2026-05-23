-- Fake Sonatype Nexus Repository (handler: lua, HTTP 8081). Nexus has had
-- pre-auth RCE / path-traversal CVEs and hosts build artifacts. Serves the
-- status endpoint and captures repository / REST probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization",(h:gsub("[\r\n]",""))); flag("http-auth-attempt") end
end
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Nexus/3.68.1-02\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("nexus-access")
path = path or "/"
if path:find("^/service/rest/v1/status") then
  send("200 OK", "application/json", '{"version":"3.68.1-02","edition":"OSS"}')
elseif path:find("^/service/rest/") or path:find("^/repository/") then
  meta("nexus_path", path)
  flag("nexus-repo-access")
  send("404 Not Found", "application/json", '{"message":"not found"}')
else
  send("200 OK", "text/html", "<html><head><title>Nexus Repository Manager</title></head></html>")
end
