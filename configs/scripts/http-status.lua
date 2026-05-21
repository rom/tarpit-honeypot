-- Fake HTTP health/status endpoint (handler: lua). Demonstrates serving
-- HTTP from Lua with a live Date header, a per-source request counter, and
-- a JSON body carrying real uptime — a believable internal "status page".
-- Captures the request line + any Authorization header. Nothing executes.
--
-- Demonstrates: time.utc (Date header) + time.uptime (live value),
-- host:get/set (per-source counter), meta/flag.

-- Read the request head (bounded): first line + headers until blank line.
local reqline = conn:readline()
if reqline then meta("request_line", (reqline:gsub("[\r\n]", ""))) end
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local low = string.lower(h)
  if low:find("^authorization:") then
    meta("authorization", (h:gsub("[\r\n]", "")))
    flag("http-auth-attempt")
  end
end

local hits = (host:get("hits") or 0) + 1
host:set("hits", hits)
meta("request_number", hits)

local body = '{"status":"ok","uptime_seconds":' .. tostring(time.uptime()) ..
  ',"requests":' .. tostring(hits) .. ',"version":"' ..
  rng:choice({ "1.4.2", "1.5.0", "2.0.1" }) .. '"}'

conn:write("HTTP/1.1 200 OK\r\n")
conn:write("Date: " .. time.utc() .. "\r\n")
conn:write("Server: nginx\r\n")
conn:write("Content-Type: application/json\r\n")
conn:write("Content-Length: " .. tostring(#body) .. "\r\n")
conn:write("Connection: close\r\n\r\n")
conn:write(body)
