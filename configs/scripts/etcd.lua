-- Fake etcd (handler: lua, HTTP 2379). An unauthenticated etcd exposes the
-- whole cluster KV store (Kubernetes secrets included). Answers /version and
-- captures key reads. Nothing is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("etcd-access")
path = path or "/"
if path:find("^/version") then
  send("200 OK", '{"etcdserver":"3.5.13","etcdcluster":"3.5.0"}')
elseif path:find("^/v2/keys") or path:find("^/v3/") then
  meta("etcd_path", path)
  flag("etcd-keys-access")
  send("200 OK", '{"action":"get","node":{"dir":true}}')
else
  send("404 Not Found", '{"errorCode":100,"message":"Key not found"}')
end
