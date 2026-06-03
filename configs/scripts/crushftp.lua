-- Fake CrushFTP web interface (handler: lua, HTTP). CrushFTP is exploited via
-- CVE-2024-4040 (VFS sandbox escape / SSTI → file read & RCE) and CVE-2023-43177.
-- Serves the recognizable WebInterface + flags the vulnerable function endpoint.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^looking_glass:") then flag("crushftp-cve-2023-43177-probe") end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  if b:find("<INCLUDE>") or b:find("zip_read") then flag("crushftp-cve-2024-4040-probe") end end
local p = string.lower(path)
flag("crushftp-access")
if p:find("/webinterface/function/") then flag("crushftp-cve-2024-4040-probe") end
local html = "<html><head><title>CrushFTP WebInterface</title></head><body>CrushFTP</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: CrushFTP HTTP Server\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
