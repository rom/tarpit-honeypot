-- Dynamic IoT-device login console (handler: lua).
--
-- Demonstrates the dynamic-response API:
--   personality()  per-host hostname / firmware (stable per source IP)
--   conn:write / conn:readline   drive the socket
--   sleep + rng    jittered, deterministic-per-host timing (timers/delays)
--   host:get/set   per-source persistent state across reconnects
--   meta / flag    record captured creds + an anomaly into the event
--
-- Nothing here executes anything; it just captures and responds.

local p = personality()

-- Dynamic banner: rotate firmware/version per host.
conn:write(p.hostname .. " (fw " .. p.firmware .. ")\r\n")
conn:write("login: ")
local user = conn:readline()
conn:write("Password: ")
local pass = conn:readline()

if user then meta("user", user) end
if pass then meta("pass", pass) end
if user and pass then flag("login-attempt") end

-- Per-host, deterministic delay before the rejection (looks like a real
-- box doing a crypt() check; same host always sees the same jitter).
sleep(200 + rng:int(400))

-- Per-source attempt counter persists across connections.
local tries = (host:get("tries") or 0) + 1
host:set("tries", tries)
meta("attempt_number", tries)

conn:write("\r\nLogin incorrect\r\n")
