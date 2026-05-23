-- Fake Prometheus (handler: lua, HTTP 9090). An exposed Prometheus leaks
-- the whole target inventory + metrics and its query API can be abused for
-- SSRF. Answers /-/healthy, /api/v1/status/buildinfo and a tiny /metrics,
-- and captures /api/v1/query expressions. No real series.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
end

local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

path = path or "/"
if path:find("^/%-/healthy") or path:find("^/%-/ready") then
  send("200 OK", "text/plain", "Prometheus Server is Healthy.\n")
elseif path:find("^/api/v1/status/buildinfo") then
  flag("prometheus-api-access")
  send("200 OK", "application/json", '{"status":"success","data":{"version":"2.53.0","goVersion":"go1.22.4"}}')
elseif path:find("^/api/v1/targets") then
  flag("prometheus-targets-access")
  send("200 OK", "application/json", '{"status":"success","data":{"activeTargets":[]}}')
elseif path:find("^/api/v1/query") then
  meta("promql", path)
  flag("prometheus-query")
  send("200 OK", "application/json", '{"status":"success","data":{"resultType":"vector","result":[]}}')
elseif path:find("^/metrics") then
  send("200 OK", "text/plain",
    "# HELP up Target up\n# TYPE up gauge\nup{job=\"prometheus\"} 1\nprometheus_build_info{version=\"2.53.0\"} 1\n")
else
  send("302 Found", "text/plain", "")
end
