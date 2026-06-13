-- Fake Apache Flink Dashboard / JobManager REST (handler: lua, HTTP 8081). The
-- dashboard REST API is unauthenticated: /jars/upload + run is direct RCE, and
-- CVE-2020-17519 lets /jobmanager/logs/..%252f..%252f read arbitrary files.
-- Decoy only — no jar runs, the "file" returned is a canned decoy.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
if clen > 0 and clen < 65536 then conn:read(clen) end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("flink-dashboard-probe")
meta("intent", "Apache Flink dashboard probe — unauthenticated JobManager")

if path:find("%.%.%%252f") or path:find("%.%.%%2f") or path:find("/jobmanager/logs/%.%.") then
  flag("flink-cve-2020-17519")
  meta("intent", "Apache Flink directory traversal (CVE-2020-17519) — arbitrary file read")
  send("200 OK", "text/plain", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
elseif path:find("/jars/upload") then
  flag("flink-jar-upload")
  meta("intent", "Apache Flink jar upload — staging remote code execution")
  send("200 OK", "application/json",
    '{"filename":"/tmp/flink-web-upload/' .. rng:hex(8) .. '_job.jar","status":"success"}')
elseif path:find("/config") or path:find("/overview") then
  send("200 OK", "application/json",
    '{"flink-version":"1.16.0","taskmanagers":2,"slots-total":8,"slots-available":8,"jobs-running":0}')
else
  send("200 OK", "text/html",
    "<html><head><title>Apache Flink Web Dashboard</title></head><body></body></html>")
end
