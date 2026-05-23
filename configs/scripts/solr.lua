-- Fake Apache Solr (handler: lua, HTTP 8983). Solr's admin API + config
-- have repeatedly enabled RCE (CVE-2019-17558 Velocity, etc.). Serves the
-- system-info admin endpoint and captures core / config probes.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("solr-access")
path = path or "/"
if path:find("^/solr/admin/info/system") then
  flag("solr-admin-access")
  send("200 OK", '{"lucene":{"solr-spec-version":"9.6.0"},"jvm":{"version":"17.0.11"},"system":{"name":"Linux"}}')
elseif path:find("^/solr/admin/cores") then
  flag("solr-core-enumeration")
  send("200 OK", '{"responseHeader":{"status":0},"status":{"prod":{"name":"prod"}}}')
elseif path:find("config") or path:find("dataimport") or path:find("replication") then
  flag("solr-config-access")
  send("200 OK", '{"responseHeader":{"status":0}}')
else
  send("200 OK", '{"responseHeader":{"status":0,"QTime":1}}')
end
