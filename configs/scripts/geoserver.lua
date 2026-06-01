-- Fake GeoServer (handler: lua, HTTP 8080). GeoServer's OGC endpoints evaluate
-- property names as JXPath expressions (CVE-2024-36401) for unauthenticated
-- RCE, and the web-admin is a frequent target. Serves a believable WFS
-- capabilities stub and captures the valueReference/exec evaluation probe.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
local body = ""
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  body = conn:read(clen) or ""
end

local ver = rng:choice({ "2.23.2", "2.24.1", "2.22.0", "2.25.0" })
local full = string.lower((reqline or "") .. " " .. body)
local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Jetty(9.4.51.v20230217)\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b))
  conn:write("\r\nConnection: close\r\n\r\n" .. b)
end

flag("geoserver-access")
if full:find("valuereference=exec", 1, true) or full:find("java.lang.runtime", 1, true) or full:find("exec(", 1, true) then
  flag("geoserver-jxpath-rce") -- CVE-2024-36401 evaluation RCE primitive
  meta("geoserver_probe", (reqline or ""):sub(1, 256))
  send("200 OK", "text/xml", '<?xml version="1.0"?><ows:ExceptionReport version="2.0.0"><ows:Exception/></ows:ExceptionReport>')
elseif full:find("request=getcapabilities") or full:find("/ows") or full:find("/wfs") or full:find("/wms") then
  flag("geoserver-ogc-probe")
  send("200 OK", "text/xml", '<?xml version="1.0"?><wfs:WFS_Capabilities version="2.0.0" updateSequence="' ..
    tostring(rng:int(99)) .. '"><ows:ServiceIdentification><ows:Title>GeoServer Web Feature Service</ows:Title>' ..
    '</ows:ServiceIdentification></wfs:WFS_Capabilities>')
elseif (path or ""):lower():find("/web") then
  flag("geoserver-admin-probe")
  send("200 OK", "text/html", "<html><title>GeoServer: Welcome</title><body>GeoServer " .. ver .. "</body></html>")
else
  send("200 OK", "text/html", "<html><body>GeoServer " .. ver .. "</body></html>")
end
