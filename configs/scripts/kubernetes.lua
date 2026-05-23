-- Fake Kubernetes API server (handler: lua, HTTPS 6443 / HTTP 8080). An
-- exposed kube-apiserver — especially with anonymous access — is full cluster
-- compromise. Answers /version, captures the bearer token and the API path
-- probed (/api, /apis, /api/v1/secrets). Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:%s*bearer") then
    meta("k8s_bearer", (h:gsub("[\r\n]", "")))
    flag("k8s-token-presented")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("k8s-api-access")
path = path or "/"
if path:find("^/version") then
  send("200 OK", '{"major":"1","minor":"29","gitVersion":"v1.29.4","platform":"linux/amd64"}')
elseif path:find("secrets") or path:find("^/api/v1/namespaces") then
  meta("k8s_path", path)
  flag("k8s-resource-access")
  send("403 Forbidden", '{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}')
elseif path:find("^/api") or path:find("^/healthz") then
  meta("k8s_path", path)
  send("200 OK", '{"kind":"APIVersions","versions":["v1"]}')
else
  send("403 Forbidden", '{"kind":"Status","status":"Failure","code":403}')
end
