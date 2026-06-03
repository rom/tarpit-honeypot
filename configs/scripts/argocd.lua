-- Fake Argo CD (handler: lua, HTTP). GitOps controller; exposed instances let an
-- attacker reach the API and deploy workloads. Serves the recognizable Argo CD UI
-- + captures the bearer token + flags API probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^cookie:") and h:find("argocd.token") then meta("argocd_token", (h:gsub("[\r\n]", ""))); flag("argocd-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end
  local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("\"username\"%s*:%s*\"([^\"]*)") if u then meta("auth_user", u); flag("argocd-login-attempt") end end
local p = string.lower(path)
flag("argocd-access")
if p:find("/api/v1/applications") or p:find("/api/v1/session") then flag("argocd-api-probe") end
local html = "<html><head><title>Argo CD</title></head><body><div id='app'>Argo CD</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
