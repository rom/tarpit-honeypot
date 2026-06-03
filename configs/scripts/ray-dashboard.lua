-- Fake Ray dashboard / Jobs API (handler: lua, HTTP). The Ray AI-compute cluster
-- dashboard exposes an unauthenticated Jobs API (CVE-2023-48022 "ShadowRay") that
-- runs arbitrary commands. Serves the recognizable Ray dashboard + flags job submit.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("entrypoint") then flag("ray-cve-2023-48022-probe") end end
local p = string.lower(path)
flag("ray-access")
if p:find("/api/jobs/") or p:find("/api/job_agent/") then flag("ray-jobs-api-probe") end
local body = '{"result":true,"data":{"clusterStatus":{"rayVersion":"2.9.0"}}}'
conn:write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
