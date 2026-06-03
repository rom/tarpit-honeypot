-- Fake Palo Alto GlobalProtect portal (handler: lua, HTTP). PAN-OS GlobalProtect
-- is mass-exploited via CVE-2024-3400 (unauth command injection through the
-- SESSID cookie path-traversal in /ssl-vpn/hipreport.esp) and brute-forced on
-- the portal login. Serves the recognizable GlobalProtect page and flags the
-- known endpoints + a traversal/command-injection SESSID.
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
  if hl:find("^cookie:") and h:find("SESSID") then
    meta("gp_sessid", (h:gsub("[\r\n]", "")))
    if h:find("%.%.") or h:find("[`;|&]") then flag("paloalto-cve-2024-3400-probe") end
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  meta("post_body", conn:read(clen) or "")
end

local p = string.lower(path)
flag("paloalto-globalprotect-access")
if p:find("/ssl%-vpn/hipreport.esp") or p:find("/global%-protect/portal") then
  flag("paloalto-globalprotect-probe")
end
if p:find("/ssl%-vpn/") and (p:find("%.%.") or p:find("hipreport")) then
  flag("paloalto-cve-2024-3400-probe")
end

local html = "<html><head><title>GlobalProtect Portal</title></head><body>" ..
  "<div id='heading'>GlobalProtect Portal</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: PanWeb Server/ -\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: PHPSESSID=" .. rng:hex(13) .. "; path=/; secure; HttpOnly\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
