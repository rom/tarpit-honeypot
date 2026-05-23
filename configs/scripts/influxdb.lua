-- Fake InfluxDB (handler: lua, HTTP 8086). An open InfluxDB exposes time-series
-- data and (v1) often allows unauthenticated queries. Answers /ping + /health
-- and captures the query string / database probed. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("influx_auth", (h:gsub("[\r\n]", "")))
    flag("influxdb-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nX-Influxdb-Version: 1.8.10\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("influxdb-access")
path = path or "/"
if path:find("^/ping") then
  conn:write("HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 1.8.10\r\nConnection: close\r\n\r\n")
elseif path:find("^/health") then
  send("200 OK", '{"name":"influxdb","status":"pass","version":"1.8.10"}')
elseif path:find("^/query") or path:find("^/api/v2/query") then
  meta("influx_query", path)
  flag("influxdb-query")
  send("200 OK", '{"results":[{"statement_id":0}]}')
else
  send("404 Not Found", '{"error":"not found"}')
end
