-- Fake Apache Kafka Connect REST API (handler: lua, HTTP 8083). The connector
-- API is unauthenticated; a connector config carrying a JNDI/JAAS URL triggers
-- CVE-2023-25194 (JndiLoginModule deserialization RCE). Decoy only — the
-- connector is never created and nothing is deserialized.

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

flag("kafka-connect-probe")
meta("intent", "Kafka Connect REST probe — unauthenticated connector API")

if method == "POST" and path:find("/connectors") then
  if body:find("jndi:", 1, true) or body:find("JndiLoginModule", 1, true) or body:find("sasl.jaas.config", 1, true) then
    flag("kafka-connect-cve-2023-25194")
    meta("intent", "Kafka Connect JNDI/JAAS injection (CVE-2023-25194) — RCE attempt")
  end
  send("201 Created", "application/json", '{"name":"decoy-connector","config":{},"tasks":[],"type":"source"}')
elseif path:find("/connector%-plugins") then
  send("200 OK", "application/json",
    '[{"class":"io.confluent.connect.jdbc.JdbcSourceConnector","type":"source","version":"10.7.0"}]')
elseif path:find("/connectors") then
  send("200 OK", "application/json", "[]")
else
  send("200 OK", "application/json",
    '{"version":"3.5.0","commit":"' .. rng:hex(8) .. '","kafka_cluster_id":"' .. personality().serial .. '"}')
end
