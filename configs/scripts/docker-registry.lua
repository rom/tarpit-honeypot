-- Fake Docker Registry v2 (handler: lua, HTTP 5000). An open registry leaks
-- every image (and the secrets baked into them) via /v2/_catalog. Answers the
-- /v2/ version probe and captures the catalog / manifest path + any auth.
-- Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("registry_auth", (h:gsub("[\r\n]", "")))
    flag("registry-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nDocker-Distribution-Api-Version: registry/2.0\r\n")
  conn:write("Content-Type: application/json\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end
flag("registry-access")
path = path or "/"
if path == "/v2/" or path == "/v2" then
  send("200 OK", "{}")
elseif path:find("^/v2/_catalog") then
  flag("registry-catalog-access")
  send("200 OK", '{"repositories":[]}')
elseif path:find("^/v2/") then
  meta("registry_path", path)
  flag("registry-manifest-access")
  send("401 Unauthorized", '{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}')
else
  send("404 Not Found", '{"errors":[{"code":"NOT_FOUND"}]}')
end
