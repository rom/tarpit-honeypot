-- Fake Apache OFBiz (handler: lua, HTTP). OFBiz is hit by CVE-2023-49070 /
-- CVE-2023-51467 (XML-RPC + auth bypass) and CVE-2024-27348 (screen-render RCE
-- via requirePasswordChange=Y). Serves the recognizable OFBiz webtools + flags
-- the known endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("ofbiz-access")
if p:find("requirepasswordchange=y") then flag("ofbiz-cve-2024-27348-probe") end
if p:find("/webtools/control/xmlrpc") then flag("ofbiz-cve-2023-49070-probe") end
if p:find("/webtools/control/") then flag("ofbiz-webtools-probe") end
local html = "<html><head><title>OFBiz</title></head><body>Apache OFBiz. The Apache Open For Business Project</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: OFBiz.Visitor=" .. rng:hex(13) .. "; Path=/\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
