-- Fake HashiCorp Consul HTTP API (handler: lua, HTTP 8500). An ACL-less
-- Consul exposes the whole service catalog + KV store and can run health
-- checks (RCE). Answers agent/self + catalog and captures KV / catalog
-- access. No real data.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^x%-consul%-token:") then
    meta("consul_token", (h:gsub("[\r\n]", "")))
    flag("http-auth-attempt")
  end
end

local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nX-Consul-Index: " .. tostring(rng:int(99999)) .. "\r\n")
  conn:write("Content-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

path = path or "/"
if path:find("^/v1/agent/self") then
  flag("consul-api-access")
  send("200 OK", '{"Config":{"Datacenter":"dc1","NodeName":"consul-01","Server":true,"Version":"1.18.1"}}')
elseif path:find("^/v1/catalog/services") then
  flag("consul-catalog-access")
  send("200 OK", '{"consul":[],"web":["primary"],"db":["primary"],"vault":[]}')
elseif path:find("^/v1/kv/") then
  flag("consul-kv-access")
  send("200 OK", '[]')
else
  send("404 Not Found", "")
end
