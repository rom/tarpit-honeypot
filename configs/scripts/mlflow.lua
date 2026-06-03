-- Fake MLflow tracking server (handler: lua, HTTP). MLflow is exploited via
-- CVE-2023-6018 / CVE-2023-6014 / CVE-2024-37052-class path traversal + model
-- write → RCE, and exposed servers leak artifacts. Serves the recognizable MLflow
-- API + flags the artifact / model endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("artifact_location") and b:find("%.%.") then flag("mlflow-path-traversal-probe") end
  if b:find("source") and b:find("file://") then flag("mlflow-model-rce-probe") end end
local p = string.lower(path)
flag("mlflow-access")
if p:find("/api/2.0/mlflow/") then flag("mlflow-api-probe") end
if p:find("/model%-versions/get%-artifact") or p:find("/get%-artifact") then flag("mlflow-cve-2023-6018-probe") end
local body = '{"experiments":[{"experiment_id":"0","name":"Default"}]}'
conn:write("HTTP/1.1 200 OK\r\nServer: gunicorn\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
