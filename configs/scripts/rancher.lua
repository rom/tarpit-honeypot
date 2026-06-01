-- Fake Rancher (handler: lua, HTTP 443/8443). Rancher manages fleets of
-- Kubernetes clusters; an exposed/compromised Rancher API is whole-fleet
-- takeover. Serves the ping + version endpoints, captures API-token use and
-- cluster/kubeconfig enumeration. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^authorization:") and hl:find("bearer") then
    meta("rancher_token", (h:gsub("[\r\n]", "")))
    flag("rancher-api-token-use")
  end
end

local ver = rng:choice({ "v2.7.5", "v2.8.1", "v2.6.13", "v2.8.5" })
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

flag("rancher-access")
path = path or "/"
local p = string.lower(path)
if p:find("/ping") then
  send("200 OK", "text/plain", "pong")
elseif p:find("/rancherversion") or p:find("/v3/settings/server%-version") then
  flag("rancher-recon")
  send("200 OK", "application/json", '{"Version":"' .. ver .. '","GitCommit":"' .. rng:hex(8) .. '"}')
elseif p:find("/v3/clusters") or p:find("kubeconfig") then
  flag("rancher-cluster-enum") -- fleet/kubeconfig enumeration = takeover recon
  send("401 Unauthorized", "application/json", '{"type":"error","status":"401","message":"must authenticate"}')
elseif p:find("/v3") or p:find("/v1") then
  send("401 Unauthorized", "application/json", '{"type":"error","status":"401","message":"Unauthorized"}')
else
  send("200 OK", "text/html", "<html><head><title>Rancher</title></head><body>Rancher " .. ver .. "</body></html>")
end
