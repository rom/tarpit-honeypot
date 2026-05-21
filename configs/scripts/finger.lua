-- Fake finger service (handler: lua, port 79). Returns a believable user
-- list with live "Login Time" timestamps and rotating idle values, and
-- captures the queried user (finger is a classic recon service). Nothing
-- is executed.
--
-- Demonstrates: time.utc (live timestamps), rng (per-row variation),
-- meta/flag (recon capture).

local q = conn:readline()
if q then
  local user = (q:gsub("[\r\n]", ""))
  if #user > 0 then
    meta("finger_query", user)
    flag("finger-query")
  end
end

conn:write("Login      Name              Tty      Idle  Login Time\r\n")
local users = { "root", "admin", "operator", "backup", "svc-deploy" }
for _, u in ipairs(users) do
  local row = u
  while #row < 11 do row = row .. " " end
  conn:write(row .. u .. "            pts/" .. tostring(rng:int(8)) ..
    "    " .. tostring(rng:int(180)) .. "m   " .. time.utc() .. "\r\n")
end
