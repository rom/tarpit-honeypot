-- Fake Apache Airflow web UI (handler: lua, HTTP 8080). An exposed Airflow
-- with default creds = arbitrary code execution (DAGs run shell). Serves
-- /health + /api/v1/dags, captures login posts.
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
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: gunicorn\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("airflow-access")
path = path or "/"
if path:find("^/health") then
  send("200 OK", "application/json", '{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"}}')
elseif path:find("^/api/v1/dags") then
  flag("airflow-dag-access")
  send("403 Forbidden", "application/json", '{"detail":"Forbidden","status":403}')
elseif method == "POST" and path:find("/login") then
  flag("airflow-login-attempt")
  send("401 Unauthorized", "text/html", "<html><body>Invalid login</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Airflow</title></head><body>Sign In</body></html>")
end
