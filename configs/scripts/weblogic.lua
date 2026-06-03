-- Fake Oracle WebLogic (handler: lua, HTTP 7001). One of the most-exploited
-- middlewares (T3/IIOP deser, wls-wsat, console paths). Flags the classic RCE
-- paths and captures the console login.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
local body = ""; if clen > 0 then if clen > 16384 then clen = 16384 end body = conn:read(clen) or "" end
local function send(code, ctype, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: Oracle WebLogic Server\r\nContent-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("weblogic-access")
local p = string.lower(path or "/")
if p:find("/wls%-wsat/") then flag("weblogic-wlswsat-rce-probe")    -- CVE-2017-10271 / CVE-2019-2725
elseif p:find("/_async/") then flag("weblogic-async-rce-probe")     -- CVE-2019-2725
elseif p:find("/console/css/%%") or p:find("/console/images/%%") then flag("weblogic-console-auth-bypass") -- CVE-2020-14882
end
if body:lower():find("<work:") or body:lower():find("coherence") or body:lower():find("java.lang.runtime") then flag("weblogic-deserialization-probe") end
local u = body:match("j_username=([^&]*)"); local pw = body:match("j_password=([^&]*)")
if u then meta("auth_user", u) end; if pw then meta("auth_pass", pw) end
if u or pw then flag("weblogic-login-attempt") end
send("200 OK", "text/html", "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body><form action=/console/j_security_check method=post><input name=j_username><input type=password name=j_password></form></body></html>")
