-- Fake Apache Hadoop YARN ResourceManager REST API (handler: lua, HTTP 8088).
-- An unauthenticated ResourceManager lets anyone create + submit an application
-- (/ws/v1/cluster/apps/new-application then POST /ws/v1/cluster/apps) and run a
-- shell command on the cluster — the classic mass-cryptojacking RCE. Nothing is
-- ever launched; the submission (and any embedded command) is captured.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body = ""
if clen > 0 and clen < 65536 then body = conn:read(clen) or "" end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("hadoop-yarn-rm-probe")
meta("intent", "Hadoop YARN ResourceManager probe — unauthenticated cluster API")

if path:find("/new%-application") then
  flag("hadoop-yarn-new-application")
  send("200 OK", "application/json",
    '{"application-id":"application_' .. tostring(time.now()) .. '_0001",' ..
    '"maximum-resource-capability":{"memory":8192,"vCores":4}}')
elseif method == "POST" and path:find("/ws/v1/cluster/apps") then
  flag("hadoop-yarn-app-submit")
  meta("intent", "Hadoop YARN application submission — unauthenticated RCE attempt")
  if body:find("command", 1, true) or body:find("am%-container%-spec") then
    meta("yarn_command_present", true)
  end
  send("202 Accepted", "application/json", "")
elseif path:find("/ws/v1/cluster") or path:find("/cluster") then
  send("200 OK", "application/json",
    '{"clusterInfo":{"id":' .. tostring(time.now()) ..
    ',"haState":"ACTIVE","resourceManagerVersion":"3.3.6","state":"STARTED"}}')
else
  send("200 OK", "text/html",
    "<html><head><title>All Applications</title></head><body>" ..
    "<h1>Hadoop ResourceManager</h1></body></html>")
end
