-- Fake VMware ESXi host UI (handler: lua, HTTP). ESXi hosts are mass-ransomwared
-- (ESXiArgs) and probed via the /ui and SOAP /sdk endpoints + OpenSLP CVEs.
-- Serves the recognizable ESXi welcome + flags the SDK/MOB endpoints.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("authorization", (h:gsub("[\r\n]", ""))); flag("esxi-auth-attempt") end end
local p = string.lower(path)
flag("esxi-access")
if p:find("/sdk") then flag("esxi-soap-sdk-probe") end
if p:find("/mob") then flag("esxi-mob-probe") end
local ver = rng:choice({ "7.0.3", "6.7.0", "8.0.2" })
meta("esxi_version", ver)
local html = "<html><head><title>VMware ESXi</title></head><body><div id='formContainer'>VMware ESXi " .. ver .. "</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: VMware ESXi/" .. ver .. " httpd\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
