-- Fake GoCD continuous-delivery server (handler: lua, HTTP 8153). CVE-2021-43287
-- lets the unauthenticated business-continuity add-on disclose the full
-- cruise-config.xml (which holds pipeline secrets / encrypted credentials).
-- Decoy only — the config returned is a minimal canned stub.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
if clen > 0 and clen < 65536 then conn:read(clen) end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("gocd-probe")
meta("intent", "GoCD server probe")

if path:find("business%-continuity") then
  flag("gocd-cve-2021-43287")
  meta("intent", "GoCD business-continuity config disclosure (CVE-2021-43287)")
  send("200 OK", "application/xml",
    '<?xml version="1.0" encoding="utf-8"?>\n<cruise schemaVersion="135">' ..
    '<server artifactsdir="artifacts"></server></cruise>')
elseif path:find("/go/api") then
  send("200 OK", "application/vnd.go.cd.v1+json", '{"version":"23.1.0","build_number":"16384"}')
else
  send("200 OK", "text/html",
    "<html><head><title>GoCD</title></head><body><div id='application'></div></body></html>")
end
