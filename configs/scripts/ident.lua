-- Fake ident / auth server (handler: lua, port 113, RFC 1413). Answers a
-- "lport,rport" query with a stable per-source USERID so a scanner mapping
-- service owners gets a consistent (fake) answer. Captures the query.
--
-- Demonstrates: personality (stable per-source username), meta/flag.

local p = personality()
local users = { "www-data", "nobody", "operator", "admin", "svc" }
-- Stable per-source pick (rng is seeded per source, so this is consistent).
local user = users[(rng:int(#users)) + 1]

local line = conn:readline()
if line then
  local q = (line:gsub("[\r\n]", ""))
  meta("ident_query", q)
  flag("ident-query")
  -- Echo the port pair back per the protocol: "lport,rport:USERID:UNIX:user"
  local ports = q
  if #ports == 0 then ports = "0,0" end
  conn:write(ports .. " : USERID : UNIX : " .. user .. "\r\n")
else
  conn:write("0,0 : ERROR : NO-USER\r\n")
end
