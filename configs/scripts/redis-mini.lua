-- Fake Redis (handler: lua). Low-interaction RESP responder with a
-- dynamic INFO: rotating redis_version, live uptime_in_seconds, and a
-- per-source connected_clients counter that persists across reconnects.
-- Captures AUTH attempts. Nothing is executed.
--
-- Demonstrates: rng:choice (rotating banner), time.uptime (live counter),
-- host:get/set (per-source counter), flag/meta (detection).

local ver = rng:choice({ "6.2.14", "7.0.15", "7.2.4", "7.4.0" })

local function info()
  local clients = (host:get("clients") or 0) + 1
  host:set("clients", clients)
  local body = table.concat({
    "# Server",
    "redis_version:" .. ver,
    "redis_mode:standalone",
    "os:Linux 5.15.0-91-generic x86_64",
    "run_id:" .. rng:hex(20),
    "tcp_port:6379",
    "uptime_in_seconds:" .. tostring(time.uptime()),
    "# Clients",
    "connected_clients:" .. tostring(clients),
    "# Keyspace",
    "db0:keys=" .. tostring(10 + rng:int(500)) .. ",expires=0",
  }, "\r\n") .. "\r\n"
  return "$" .. tostring(#body) .. "\r\n" .. body .. "\r\n"
end

for _ = 1, 16 do
  local line = conn:readline()
  if not line then break end
  local cmd = string.upper((line:gsub("[\r\n]", "")))
  if cmd:find("PING") then
    conn:write("+PONG\r\n")
  elseif cmd:find("INFO") then
    conn:write(info())
  elseif cmd:find("AUTH") then
    meta("redis_auth", line)
    flag("redis-auth-attempt")
    conn:write("-ERR invalid password\r\n")
  elseif cmd:find("CONFIG") then
    flag("redis-config-access")
    conn:write("*0\r\n")
  elseif cmd:find("QUIT") then
    conn:write("+OK\r\n")
    break
  elseif cmd:find("^%*") or cmd:find("^%$") then
    -- RESP multibulk framing line ("*3", "$4"); wait for the verb line.
  elseif #cmd > 0 then
    conn:write("-ERR unknown command\r\n")
  end
end
