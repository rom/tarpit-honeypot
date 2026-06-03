-- Fake Cisco ASA AnyConnect / WebVPN portal (handler: lua, HTTP). Cisco ASA
-- SSL-VPN is probed for CVE-2020-3452 (unauth file read via path traversal on
-- /+CSCOT+/translation-table?...&filename=../) and the +webvpn+ login is
-- brute-forced. Serves the recognizable WebVPN portal and flags the traversal.
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
  local u = body:match("username=([^&]*)")
  if u then meta("webvpn_user", u); flag("cisco-asa-login-attempt") end
end

local p = string.lower(path)
flag("cisco-asa-access")
if p:find("/%+cscot%+/") and (p:find("%.%.") or p:find("filename=")) then
  flag("cisco-cve-2020-3452-probe")
end
if p:find("/%+webvpn%+/") or p:find("/+cscoe+/logon.html") then flag("cisco-webvpn-probe") end

local html = "<html><head><title>SSL VPN Service</title></head><body>" ..
  "<div>Cisco AnyConnect Secure Mobility Client</div></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Cisco ASA\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: webvpn=" .. rng:hex(20) .. "; path=/; secure\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
