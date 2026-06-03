-- Fake VMware vCenter / vSphere Client (handler: lua, HTTP). vCenter is a prime
-- target: CVE-2021-21972 (/ui/vropspluginui unauth RCE), CVE-2021-44228
-- (Log4Shell via login fields), and the /websso SAML endpoints. Serves the
-- recognizable vSphere landing + captures probed paths and JNDI payloads.
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
  if h:find("jndi:") then flag("log4shell-attempt"); meta("jndi_header", (h:gsub("[\r\n]", ""))) end
end
local body = ""
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("jndi:") then flag("log4shell-attempt") end
end

local build = rng:choice({ "7.0.3-20990077", "8.0.2-22617221", "6.7.0-17138064" })
meta("vcenter_build", build)
local p = string.lower(path)
flag("vcenter-access")
if p:find("/ui/vropspluginui") or p:find("/statsreport") then flag("vcenter-cve-2021-21972-probe") end
if p:find("/websso") or p:find("/sts/") then flag("vcenter-sso-probe") end

local html = "<html><head><title>vSphere Client</title></head><body>" ..
  "<div id='app'>VMware vSphere</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Server\r\nContent-Type: text/html; charset=UTF-8\r\n")
conn:write("Set-Cookie: VSPHERE-UI-JSESSIONID=" .. rng:hex(16) .. "; Path=/; Secure; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
