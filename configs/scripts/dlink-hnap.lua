-- Fake D-Link router admin / HNAP (handler: lua, HTTP). SOHO D-Link routers are
-- mass-exploited via the HNAP1 SOAP endpoint (CVE-2015-2051 / many variants:
-- command injection in the SOAPAction header) and default admin logins, feeding
-- Mirai-class botnets. Serves a believable D-Link admin page + captures the
-- HNAP SOAPAction and any login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^soapaction:") then
    meta("hnap_soapaction", (h:gsub("[\r\n]", ""))); flag("dlink-hnap-probe")
    if h:find("[`;|&]") or h:find("%$%(") then flag("dlink-hnap-command-injection") end
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("[`;|]") and (string.lower(path):find("hnap") or true) then
    -- command metacharacters in an HNAP body are the injection payload
    if body:find("GetDeviceSettings") or body:find("`") then flag("dlink-hnap-command-injection") end
  end
end

local model = rng:choice({ "DIR-859", "DIR-645", "DIR-815", "DSL-2750B" })
meta("dlink_model", model)
local p = string.lower(path)
flag("dlink-access")
if p:find("/hnap1") then flag("dlink-hnap-probe") end

local html = "<html><head><title>D-LINK SYSTEMS, INC. | WIRELESS ROUTER | " .. model ..
  "</title></head><body>D-Link " .. model .. "</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.39\r\nContent-Type: text/html\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
