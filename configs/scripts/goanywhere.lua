-- Fake Fortra GoAnywhere MFT (handler: lua, HTTP). GoAnywhere is exploited via
-- CVE-2024-0204 (auth bypass to admin via /InitialAccountSetup.xhtml) and
-- CVE-2023-0669 (deserialization). Serves the recognizable login + flags both.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("goanywhere-access")
if p:find("/initialaccountsetup.xhtml") then flag("goanywhere-cve-2024-0204-probe") end
if p:find("/lic/accept") then flag("goanywhere-cve-2023-0669-probe") end
local html = "<html><head><title>GoAnywhere MFT</title></head><body>Fortra GoAnywhere</body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: JSESSIONID=" .. rng:hex(24) .. "; Path=/; Secure\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
