-- Fake ClickHouse HTTP interface (handler: lua, HTTP 8123). An exposed
-- ClickHouse with the default empty-password 'default' user lets anyone run
-- SQL (and read files via file()/url()). The "ping" path returns Ok, and
-- any ?query= / POSTed SQL is captured and flagged. Nothing executes.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^x%-clickhouse%-user:") then
    meta("clickhouse_user", (h:gsub("[\r\n]", "")))
  end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body_in = ""
if clen > 0 and clen < 8192 then body_in = conn:read(clen) or "" end

local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nX-ClickHouse-Server-Display-Name: clickhouse-01\r\n")
  conn:write("Content-Type: text/plain; charset=UTF-8\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

path = path or "/"
local query = path:match("[?&]query=([^&]+)") or body_in
if path:find("^/ping") then
  send("200 OK", "Ok.\n")
elseif query and #query > 0 then
  meta("clickhouse_query", query)
  flag("clickhouse-query")
  send("200 OK", "0\n")
else
  send("200 OK", "Ok.\n")
end
