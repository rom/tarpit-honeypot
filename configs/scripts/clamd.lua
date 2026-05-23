-- Fake ClamAV clamd (handler: lua, TCP 3310). Answers the unauthenticated
-- admin commands an exposed clamd exposes — PING/VERSION/STATS — and
-- captures SCAN / INSTREAM attempts. An internet-reachable clamd is a known
-- DoS / info-leak target.

local ver = rng:choice({ "ClamAV 0.103.11", "ClamAV 1.0.5", "ClamAV 1.3.1" })
local db = 27000 + rng:int(3000)

for _ = 1, 16 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""):gsub("^[nz]", ""))
  local cmd = string.upper(c)
  if cmd == "PING" then
    conn:write("PONG\n")
  elseif cmd == "VERSION" then
    conn:write(ver .. "/" .. tostring(db) .. "/" .. time.utc() .. "\n")
  elseif cmd == "STATS" then
    conn:write("POOLS: 1\nSTATE: VALID PRIMARY\nTHREADS: live 1 idle 0 max 12 idle-timeout 30\n" ..
      "QUEUE: 0 items\nMEMSTATS: heap " .. tostring(5 + rng:int(30)) .. "M\nEND\n")
  elseif cmd:find("^SCAN") or cmd:find("^CONTSCAN") or cmd:find("^MULTISCAN") then
    meta("clamd_scan", c)
    flag("clamd-scan-attempt")
    conn:write((c:match("%s+(%S+)") or "/tmp") .. ": Access denied. ERROR\n")
  elseif cmd:find("^INSTREAM") then
    flag("clamd-instream-attempt")
    conn:write("INSTREAM: size limit exceeded. ERROR\n")
  elseif cmd == "RELOAD" then
    conn:write("RELOADING\n")
  elseif cmd == "SHUTDOWN" then
    flag("clamd-shutdown-attempt")
    break
  elseif #cmd > 0 then
    conn:write("UNKNOWN COMMAND\n")
  end
end
