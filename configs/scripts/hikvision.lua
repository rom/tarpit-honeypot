-- Fake Hikvision IP camera (handler: lua, HTTP). ISAPI endpoint; CVE-2021-36260
-- command injection via the webLanguage parameter is mass-scanned.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("http-auth-attempt") end end
local body = ""; if clen > 0 then if clen > 8192 then clen = 8192 end body = conn:read(clen) or "" end
local function send(code, ctype, b) conn:write("HTTP/1.1 " .. code .. "\r\nServer: App-webs/\r\nContent-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b) end
flag("hikvision-access")
local p = string.lower(path or "/")
if p:find("/sdk/weblanguage") then flag("hikvision-cve-2021-36260-probe") end
if body:lower():find("<weblanguage>") or body:find("`") or body:find("%$%(") then flag("hikvision-cmd-injection-payload") end
if p:find("/system/deviceinfo") then flag("hikvision-isapi-enum") end
send("200 OK", "application/xml", '<?xml version="1.0"?><DeviceInfo><deviceName>IPCamera</deviceName><model>DS-2CD2042WD-I</model><firmwareVersion>V5.4.5</firmwareVersion></DeviceInfo>')
