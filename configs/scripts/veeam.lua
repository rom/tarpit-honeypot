-- Fake Veeam Backup & Replication REST API (handler: lua, HTTP 9419). Veeam is
-- a top ransomware target: CVE-2023-27532 leaks stored credentials from the
-- config DB via the unauthenticated Veeam.Backup.Service, and the REST login
-- is brute-forced for the backup console. Decoy only — captures the OAuth2
-- password grant, returns no real data.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
method = method or "GET"; path = path or "/"
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body = ""
if clen > 0 and clen < 65536 then body = conn:read(clen) or "" end

local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("veeam-probe")
meta("intent", "Veeam Backup & Replication probe")

if path:find("/api/oauth2/token") or path:find("/token") then
  flag("veeam-auth-attempt")
  local u = body:match("username=([^&\r\n]+)")
  local p = body:match("password=([^&\r\n]+)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  send("401 Unauthorized", "application/json", '{"error":"invalid_grant","message":"Invalid credentials"}')
elseif path:find("/api/v1/serverInfo") or path:find("/api") then
  send("200 OK", "application/json",
    '{"vbrId":"' .. personality().serial .. '","name":"VEEAM-BR01","buildVersion":"12.0.0.1420"}')
else
  send("200 OK", "text/html",
    "<html><head><title>Veeam Backup &amp; Replication</title></head><body></body></html>")
end
