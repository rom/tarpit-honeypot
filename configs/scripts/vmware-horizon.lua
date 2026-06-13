-- Fake VMware Horizon connection server (handler: lua, HTTP 443/8443). Horizon
-- was a flagship Log4Shell (CVE-2021-44228) mass-exploitation target: the JNDI
-- string was delivered through the /broker/xml and /portal endpoints and their
-- headers. Decoy only — the lookup is recognized and captured, never resolved.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen, hdrs = 0, ""
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  hdrs = hdrs .. h
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body = ""
if clen > 0 and clen < 65536 then body = conn:read(clen) or "" end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("vmware-horizon-probe")
meta("intent", "VMware Horizon connection-server probe")

local blob = reqline .. hdrs .. body
if blob:find("${jndi:", 1, true) or blob:find("${lower:j", 1, true) then
  flag("vmware-horizon-log4shell")
  meta("intent", "VMware Horizon Log4Shell (CVE-2021-44228) JNDI lookup")
end

if path:find("/broker/xml") then
  send("200 OK", "text/xml",
    '<?xml version="1.0"?><broker version="14.0"><result>ok</result></broker>')
else
  send("200 OK", "text/html",
    "<html><head><title>VMware Horizon</title></head><body>" ..
    "<div id='horizon-client'>VMware Horizon HTML Access</div></body></html>")
end
