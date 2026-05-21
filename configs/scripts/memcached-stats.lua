-- Fake memcached text protocol (handler: lua). Dynamic `stats` with live
-- uptime + epoch time and a per-source cmd_get counter; rotating version.
-- Write commands (set) are flagged. Nothing is stored or executed.
--
-- Demonstrates: time.uptime / time.now (live timestamps), host:get/set
-- (counter), rng (rotating values), flag/meta (detection).

local ver = rng:choice({ "1.6.21", "1.6.18", "1.6.9" })

for _ = 1, 16 do
  local line = conn:readline()
  if not line then break end
  local cmd = (line:gsub("[\r\n]", ""))
  local lc = string.lower(cmd)
  if lc:find("^version") then
    conn:write("VERSION " .. ver .. "\r\n")
  elseif lc:find("^stats") then
    local gets = host:get("gets") or 0
    local lines = {
      "STAT pid 2098",
      "STAT uptime " .. tostring(time.uptime()),
      "STAT time " .. tostring(time.now()),
      "STAT version " .. ver,
      "STAT curr_connections " .. tostring(5 + rng:int(20)),
      "STAT cmd_get " .. tostring(gets),
      "STAT cmd_set " .. tostring(rng:int(50)),
      "STAT curr_items " .. tostring(rng:int(1000)),
    }
    conn:write(table.concat(lines, "\r\n") .. "\r\nEND\r\n")
  elseif lc:find("^get ") or lc:find("^gets ") then
    host:set("gets", (host:get("gets") or 0) + 1)
    conn:write("END\r\n")
  elseif lc:find("^set ") or lc:find("^add ") or lc:find("^replace ") then
    flag("memcached-write-attempt")
    meta("memcached_set", cmd)
    conn:write("STORED\r\n")
  elseif lc:find("^quit") then
    break
  elseif #cmd > 0 then
    conn:write("ERROR\r\n")
  end
end
