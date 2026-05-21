-- Fake rsync daemon (handler: lua, port 873). Sends the @RSYNCD greeting,
-- captures the client protocol line + the module the client asks for, then
-- demands auth (so a scanner enumerating modules / trying anonymous sync is
-- recorded). Nothing is served or executed.
--
-- Demonstrates: rng (rotating protocol version), host:get/set (per-source
-- probe counter), meta/flag (module-enumeration capture).

local ver = rng:choice({ "30.0", "31.0" })
conn:write("@RSYNCD: " .. ver .. "\r\n")

-- Client echoes its own @RSYNCD version line first.
local cver = conn:readline()
if cver then meta("rsync_client", (cver:gsub("[\r\n]", ""))) end

-- Then the module name (empty line / "#list" = list modules).
local mod = conn:readline()
if mod then
  local m = (mod:gsub("[\r\n]", ""))
  meta("rsync_module", m)
  local probes = (host:get("probes") or 0) + 1
  host:set("probes", probes)
  meta("probe_number", probes)
  flag("rsync-module-probe")
  if m == "" or m == "#list" then
    conn:write("backups\r\ndata\r\nweb\r\n@RSYNCD: EXIT\r\n")
  else
    conn:write("@RSYNCD: AUTHREQD " .. rng:hex(8) .. "\r\n")
  end
end
