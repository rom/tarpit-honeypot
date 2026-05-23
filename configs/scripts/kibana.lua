-- Fake Kibana (handler: lua, HTTP 5601). Front door to Elasticsearch;
-- Kibana CVEs (e.g. prototype-pollution RCE) make it a target. Serves the
-- status API + login page, captures login posts.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)"); if n then clen = tonumber(n) end
end
if clen > 0 and clen < 8192 then meta("login_body", conn:read(clen) or "") end
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nkbn-name: kibana\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("kibana-access")
path = path or "/"
if path:find("^/api/status") then
  send("200 OK", "application/json", '{"name":"kibana","version":{"number":"8.13.4"},"status":{"overall":{"level":"available"}}}')
elseif method == "POST" and path:find("/internal/security/login") then
  flag("kibana-login-attempt")
  send("401 Unauthorized", "application/json", '{"statusCode":401,"error":"Unauthorized"}')
else
  send("200 OK", "text/html", "<html><head><title>Kibana</title></head><body>Loading Kibana</body></html>")
end
