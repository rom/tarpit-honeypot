-- Fake ManageEngine (handler: lua, HTTP). Zoho ManageEngine products
-- (ADSelfService Plus, ServiceDesk Plus, ADAudit) are relentlessly exploited
-- (CVE-2021-40539, CVE-2022-47966 SAML RCE). Captures the probed product path,
-- SAML endpoints, and login POSTs. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  if body:find("j_username=") or body:find("LOGIN_ID=") then flag("manageengine-login-attempt") end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: \r\n")
  conn:write("Content-Type: text/html; charset=UTF-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end
flag("manageengine-access")
path = path or "/"
local p = string.lower(path)
if p:find("/samlresponse") or p:find("/samllogin") or p:find("/restapi/") then
  flag("manageengine-saml-probe") -- CVE-2022-47966 SAML RCE surface
  meta("me_path", path)
  send("200 OK", "<html><body>ManageEngine</body></html>")
elseif p:find("/servicedesk") or p:find("/adselfservice") or p:find("/dana") then
  flag("manageengine-product-probe")
  meta("me_path", path)
  send("200 OK", "<html><title>ManageEngine</title><body>ServiceDesk Plus</body></html>")
else
  send("200 OK", "<html><head><title>ManageEngine</title></head><body>ManageEngine</body></html>")
end
