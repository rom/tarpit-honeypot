-- Fake RabbitMQ management API (handler: lua, HTTP 15672). Default
-- guest/guest on an exposed mgmt UI leaks every queue + lets you publish.
-- Answers /api/overview, captures Authorization (Basic guest:guest).
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization",(h:gsub("[\r\n]",""))); flag("http-auth-attempt") end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Cowboy\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("rabbitmq-api-access")
path = path or "/"
if path:find("^/api/overview") then
  send("200 OK", '{"management_version":"3.13.2","rabbitmq_version":"3.13.2","node":"rabbit@mq-01","erlang_version":"26.2"}')
elseif path:find("^/api/whoami") then
  send("200 OK", '{"name":"guest","tags":["administrator"]}')
elseif path:find("^/api/") then
  flag("rabbitmq-resource-access")
  send("200 OK", '[]')
else
  send("200 OK", "<html><head><title>RabbitMQ Management</title></head></html>")
end
