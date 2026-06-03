-- Fake JFrog Artifactory (handler: lua, HTTP). Binary repo manager; exposed
-- instances leak artifacts/creds and the API is brute-forced. Serves the
-- recognizable Artifactory banner + captures auth.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("artifactory-auth-attempt") end
  if hl:find("^x%-jfrog%-art%-api:") then meta("jfrog_api_key", (h:gsub("[\r\n]", ""))); flag("artifactory-apikey-attempt") end end
local p = string.lower(path)
flag("artifactory-access")
if p:find("/artifactory/api/") then flag("artifactory-api-probe") end
local body = '{"version":"7.71.5","revision":"77105900"}'
conn:write("HTTP/1.1 200 OK\r\nServer: Artifactory/7.71.5\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
