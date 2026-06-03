-- Fake Apache Tomcat Manager (handler: lua, HTTP). The /manager/html and
-- /host-manager apps are relentlessly brute-forced for default creds
-- (tomcat:tomcat, admin:admin) and probed for the WAR-upload RCE path. Serves a
-- believable Basic-auth challenge, captures the credentials, and flags the
-- WAR-deploy attempt. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen, auth = 0, nil
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^authorization:%s*basic") then
    auth = h:match(":%s*[Bb]asic%s+(%S+)")
    meta("authorization", (h:gsub("[\r\n]", "")))
    if auth then meta("basic_auth_b64", auth) end
    flag("tomcat-auth-attempt")
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  meta("post_body", conn:read(clen) or "")
end

local ver = rng:choice({ "9.0.83", "8.5.96", "10.1.18", "7.0.109" })
local p = string.lower(path)
flag("tomcat-access")
if p:find("/manager") or p:find("/host%-manager") then
  flag("tomcat-manager-probe")
  if p:find("/deploy") or p:find("/upload") or p:find("%.war") then
    flag("tomcat-war-deploy-attempt")
  end
  conn:write("HTTP/1.1 401 Unauthorized\r\nServer: Apache-Coyote/1.1\r\n")
  conn:write("WWW-Authenticate: Basic realm=\"Tomcat Manager Application\"\r\n")
  conn:write("Content-Type: text/html\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
else
  local body = "<html><head><title>Apache Tomcat/" .. ver .. "</title></head><body>" ..
    "<h1>Apache Tomcat/" .. ver .. "</h1><p>If you're seeing this, you've " ..
    "successfully installed Tomcat.</p></body></html>"
  conn:write("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n")
  conn:write("Connection: close\r\nContent-Length: " .. tostring(#body) .. "\r\n\r\n" .. body)
end
