-- Fake managed-switch CLI (handler: lua). Captures the login, then drops
-- into an unprivileged prompt and engages: every command is captured and
-- counted per source, "show version" reports a live uptime, and config /
-- enable attempts are flagged. Nothing is executed.
--
-- Demonstrates: personality (stable hostname prompt), host:get/set
-- (per-source command counter), time.uptime (live uptime), sleep (timing),
-- flag/meta (capture + detection).

local p = personality()
local sw = "SW-" .. string.upper(p.hostname)

conn:write("\r\nUser Access Verification\r\n\r\nUsername: ")
local user = conn:readline()
conn:write("Password: ")
local pass = conn:readline()
if user then meta("user", (user:gsub("[\r\n]", ""))) end
if pass then meta("pass", (pass:gsub("[\r\n]", ""))) end
flag("switch-login-attempt")
sleep(300 + rng:int(500))
conn:write("\r\n% Login invalid\r\n")

local prompt = sw .. ">"
conn:write("\r\n" .. prompt .. " ")
for _ = 1, 20 do
  local line = conn:readline()
  if not line then break end
  local cmd = (line:gsub("[\r\n]", ""))
  local n = (host:get("cmds") or 0) + 1
  host:set("cmds", n)
  if #cmd > 0 then meta("cmd_" .. tostring(n), cmd) end
  local lc = string.lower(cmd)
  if lc:find("show version") then
    conn:write("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\r\n")
    conn:write(sw .. " uptime is " .. tostring(math.floor(time.uptime() / 60)) .. " minutes\r\n")
  elseif lc:find("show run") or lc:find("^conf") or lc:find("write ") then
    flag("switch-config-access")
    conn:write("% Insufficient privilege level\r\n")
  elseif lc:find("^enable") then
    conn:write("Password: ")
    conn:readline()
    sleep(200 + rng:int(300))
    conn:write("% Access denied\r\n")
  elseif lc:find("^exit") or lc:find("^quit") or lc:find("^logout") then
    break
  elseif #cmd > 0 then
    conn:write("% Invalid input detected\r\n")
  end
  conn:write("\r\n" .. prompt .. " ")
end
