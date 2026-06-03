-- Fake OpenShift / Kubernetes OAuth console (handler: lua, HTTP). Exposed clusters
-- are probed at the OAuth + API endpoints; a leaked bearer token yields control.
-- Serves the recognizable OpenShift login + captures the bearer token.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("openshift-auth-attempt") end end
local p = string.lower(path)
flag("openshift-access")
if p:find("/oauth/authorize") or p:find("/oauth/token") then flag("openshift-oauth-probe") end
if p:find("/apis/") or p:find("/api/v1/namespaces") then flag("openshift-api-probe") end
local html = "<html><head><title>Log In</title></head><body><div id='login'>Red Hat OpenShift</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
