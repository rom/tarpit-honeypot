-- Fake WHOIS server (handler: lua, port 43). Reads the one-line query,
-- captures it, and returns a believable record stamped with a live
-- "Last update" timestamp. Nothing executes.
--
-- Demonstrates: time.utc (live timestamp), rng (rotating registrar),
-- meta/flag (query capture).

local query = conn:readline()
local q = "-"
if query then
  q = (query:gsub("[\r\n]", ""))
  if #q > 0 then
    meta("whois_query", q)
    flag("whois-query")
  end
end

local registrar = rng:choice({ "MarkMonitor Inc.", "GoDaddy.com, LLC", "NameCheap, Inc.", "Gandi SAS" })
conn:write("Domain Name: " .. string.upper(q) .. "\r\n")
conn:write("Registrar: " .. registrar .. "\r\n")
conn:write("Updated Date: " .. time.utc() .. "\r\n")
conn:write("Name Server: ns1." .. q .. "\r\n")
conn:write("Name Server: ns2." .. q .. "\r\n")
conn:write("DNSSEC: unsigned\r\n")
conn:write(">>> Last update of WHOIS database: " .. time.utc() .. " <<<\r\n")
