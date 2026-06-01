-- Fake Zabbix agent (handler: lua, TCP 10050). The Zabbix agent protocol is
-- a simple header ("ZBXD\1" + length) followed by an item key; exposed agents
-- allow remote item evaluation (system.run RCE on misconfigured agents,
-- CVE-2020-15803 class). Captures the requested item key, flags system.run /
-- command-execution probes, and answers with a believable agent.ping/version.
-- Nothing is executed.
local function zbx_reply(payload)
  -- ZBXD\1 + 8-byte little-endian length + payload.
  local n = #payload
  local len = string.char(
    n % 256,
    math.floor(n / 256) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256,
    0, 0, 0, 0)
  conn:write("ZBXD\1" .. len .. payload)
end

local ver = rng:choice({ "6.0.30", "6.4.15", "7.0.3", "5.0.42" })

for _ = 1, 8 do
  local line = conn:readline()
  if not line then break end
  -- Strip the optional ZBXD header if present, leaving the item key text.
  local key = line:gsub("^ZBXD.", ""):gsub("[\r\n]", "")
  key = key:gsub("^[%z\1-\31]+", "") -- drop leading length bytes / control chars
  if #key == 0 then
    -- keep reading; framing-only line
  elseif key:find("system%.run") or key:find("system%.uname") then
    meta("zabbix_item", key)
    flag("zabbix-command-exec") -- system.run[...] is the agent-RCE primitive
    zbx_reply("ZBX_NOTSUPPORTED\0Unsupported item key.")
    break
  elseif key:find("agent%.version") then
    meta("zabbix_item", key)
    zbx_reply(ver)
    break
  elseif key:find("agent%.ping") then
    zbx_reply("1")
    break
  else
    meta("zabbix_item", key)
    flag("zabbix-item-probe")
    zbx_reply("ZBX_NOTSUPPORTED\0Unsupported item key.")
    break
  end
end
