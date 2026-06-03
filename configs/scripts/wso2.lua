-- Fake WSO2 Carbon management console (handler: lua, HTTP). WSO2 products
-- (API Manager, Identity Server, EI) are exploited via CVE-2022-29464 (unauth
-- arbitrary file upload through /fileupload/toolsAny → JSP webshell). Serves the
-- recognizable Carbon login + flags the upload endpoint.
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
  if hl:find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("wso2-auth-attempt") end
end
if clen > 0 then if clen > 8192 then clen = 8192 end meta("post_body", conn:read(clen) or "") end
local p = string.lower(path)
flag("wso2-access")
if p:find("/fileupload/toolsany") or p:find("/fileupload/") then flag("wso2-cve-2022-29464-probe") end
if p:find("/carbon/admin") then flag("wso2-carbon-probe") end
local html = "<html><head><title>WSO2 Management Console</title></head><body><div id='middle'>WSO2 Carbon</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: WSO2 Carbon Server\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: JSESSIONID=" .. rng:hex(24) .. "; Path=/; Secure; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
