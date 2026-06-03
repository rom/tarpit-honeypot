-- Fake Apache Druid console (handler: lua, HTTP). Druid is exploited via
-- CVE-2021-25646 (embedded JavaScript in a sampler/parser task → RCE). Serves
-- the recognizable Druid console + flags the indexer endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("javascript") and b:find("function") then flag("druid-cve-2021-25646-probe") end end
local p = string.lower(path)
flag("druid-access")
if p:find("/druid/indexer/v1/sampler") or p:find("/druid/indexer/v1/task") then flag("druid-indexer-probe") end
local html = "<html><head><title>Apache Druid</title></head><body>Apache Druid</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: \r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
