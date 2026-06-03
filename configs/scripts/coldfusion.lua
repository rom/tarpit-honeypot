-- Fake Adobe ColdFusion administrator (handler: lua, HTTP). The
-- /CFIDE/administrator console is scanned for weak creds and for CVE-2023-26360
-- (unauth arbitrary read / deserialization RCE) and the classic
-- locale-traversal LFI on administrator/enter.cfm. Serves a believable CF admin
-- login + flags the known paths.
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
  local pw = body:match("cfadminPassword=([^&]*)")
  if pw then meta("form_pass", pw); flag("coldfusion-login-attempt") end
end

local ver = rng:choice({ "2021,0,08,330035", "2018,0,16,330000", "2023,0,01,330021" })
meta("coldfusion_version", ver)
local p = string.lower(path)
flag("coldfusion-access")
if p:find("/cfide/administrator") then flag("coldfusion-admin-probe") end
if p:find("/cf_scripts/") or p:find("locale=") and p:find("%.%.") then flag("coldfusion-cve-2023-26360-probe") end

local html = "<html><head><title>Administrator Login</title></head><body>" ..
  "<form action='/CFIDE/administrator/enter.cfm' method='post'>" ..
  "ColdFusion Administrator<input type='password' name='cfadminPassword'></form></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: CFID=" .. tostring(rng:int(90000) + 1000) .. "; path=/\r\n")
conn:write("Set-Cookie: CFTOKEN=" .. rng:hex(16) .. "; path=/\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
