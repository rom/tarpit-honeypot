-- Fake Citrix ADC / NetScaler Gateway (handler: lua, HTTP). Targeted by
-- CVE-2019-19781 (/vpn/../vpns/ directory traversal RCE) and CVE-2023-3519
-- (unauth RCE / "CitrixBleed" session theft via /oauth/idp). Serves the
-- recognizable Citrix logon page and flags the traversal + the known endpoints.
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
  meta("post_body", conn:read(clen) or "")
end

local p = string.lower(path)
flag("citrix-access")
if p:find("/vpn/%.%.") or p:find("/vpns/") then flag("citrix-cve-2019-19781-probe") end
if p:find("/oauth/idp") or p:find("/cgi/saml") then flag("citrix-cve-2023-3519-probe") end
if p:find("/logon/logonpoint") or p:find("/vpn/index.html") then flag("citrix-gateway-probe") end

local html = "<html><head><title>Citrix Gateway</title></head><body>" ..
  "<form action='/cgi/login' method='post'>NetScaler Gateway</form></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: NetScaler\r\nContent-Type: text/html\r\n")
conn:write("Set-Cookie: NSC_AAAC=" .. rng:hex(24) .. "; Secure; HttpOnly; Path=/\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
