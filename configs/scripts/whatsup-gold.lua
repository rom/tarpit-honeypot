-- Fake Progress WhatsUp Gold (handler: lua, HTTP). WhatsUp Gold is exploited via
-- CVE-2024-4885 (unauth RCE through GetFileWithoutZip) and CVE-2024-6670 (SQLi).
-- Serves the recognizable NmConsole login + flags the vulnerable handlers.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("whatsupgold-access")
if p:find("getfilewithoutzip") then flag("whatsupgold-cve-2024-4885-probe") end
if p:find("/nmconsole/") then flag("whatsupgold-console-probe") end
local html = "<html><head><title>WhatsUp Gold</title></head><body>Progress WhatsUp Gold</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
