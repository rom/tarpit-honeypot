-- Fake Traefik dashboard / API (handler: lua, HTTP 8080). An exposed Traefik
-- dashboard leaks the whole routing map (backends, middlewares, internal
-- hosts). Answers /api/version + the dashboard and captures the API path
-- probed. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("traefik-access")
path = path or "/"
if path:find("^/api/version") then
  send("200 OK", "application/json", '{"Version":"3.0.0","Codename":"beaufort"}')
elseif path:find("^/api/rawdata") or path:find("^/api/http") then
  meta("traefik_path", path)
  flag("traefik-config-access")
  send("200 OK", "application/json", '{"routers":{},"services":{},"middlewares":{}}')
elseif path:find("^/dashboard") then
  send("200 OK", "text/html", "<html><head><title>Traefik</title></head><body>Traefik Dashboard</body></html>")
else
  send("404 Not Found", "application/json", '{"error":"not found"}')
end
