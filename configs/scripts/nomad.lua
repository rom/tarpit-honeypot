-- Fake HashiCorp Nomad (handler: lua, HTTP). An exposed Nomad HTTP API with ACLs
-- disabled lets an attacker submit a job (raw_exec → RCE). Serves the recognizable
-- Nomad API + flags job submission.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^x%-nomad%-token:") then meta("nomad_token", (h:gsub("[\r\n]", ""))); flag("nomad-auth-attempt") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("raw_exec") or b:find("\"Driver\"") then flag("nomad-job-submit-probe") end end
local p = string.lower(path)
flag("nomad-access")
if p:find("/v1/jobs") or p:find("/v1/job/") then flag("nomad-api-probe") end
local body = '{"Config":{"Datacenters":["dc1"]},"version":"1.7.2"}'
conn:write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
