-- Fake Apache Spark master UI / REST (handler: lua, HTTP 8080). An exposed
-- Spark master allows unauthenticated job submission = code execution
-- (CVE-2022-33891 / the standalone REST API). Answers the master UI, captures
-- any /v1/submissions job-submit attempt + the path. Nothing is executed.
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
flag("spark-access")
path = path or "/"
if path:find("^/v1/submissions/create") or method == "POST" then
  meta("spark_path", path)
  flag("spark-job-submit")
  send("200 OK", "application/json", '{"action":"CreateSubmissionResponse","success":false}')
elseif path:find("^/json") or path:find("^/api") then
  meta("spark_path", path)
  send("200 OK", "application/json", '{"url":"spark://master:7077","workers":[],"status":"ALIVE"}')
else
  send("200 OK", "text/html", "<html><head><title>Spark Master at spark://master:7077</title></head><body>Spark Master</body></html>")
end
