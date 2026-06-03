-- Fake Telerik UI for ASP.NET AJAX (handler: lua, HTTP). Telerik UI is exploited
-- via CVE-2019-18935 (insecure deserialization in Telerik.Web.UI.dll's
-- RadAsyncUpload, often chained with CVE-2017-11317 weak encryption keys) for
-- RCE on IIS apps. Serves a believable ASP.NET response and flags the
-- Telerik.Web.UI handler endpoints.
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
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("rauPostData") or body:find("TypeName") then flag("telerik-cve-2019-18935-probe") end
end

local p = string.lower(path)
flag("telerik-access")
if p:find("telerik.web.ui.webresource.axd") then flag("telerik-cve-2017-11317-probe") end
if p:find("telerik.web.ui.dialoghandler") or p:find("telerik.web.ui.spellcheckhandler") then
  flag("telerik-handler-probe")
end

local html = "<html><head><title>RadControls</title></head><body>" ..
  "Telerik.Web.UI</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-AspNet-Version: 4.0.30319\r\n")
conn:write("X-Powered-By: ASP.NET\r\nContent-Type: text/html\r\nConnection: close\r\n")
conn:write("Content-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
