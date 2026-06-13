-- Fake Progress MOVEit Transfer (handler: lua, HTTP 443). MOVEit was the Cl0p
-- mass-exploitation event of 2023: CVE-2023-34362 is an unauthenticated SQL
-- injection through the web UI / MOVEitISAPI that deployed the "human2.aspx"
-- webshell. Decoy only — login + the webshell path + the SQLi surface are
-- captured; no database and no shell exist.

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
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end

flag("moveit-probe")
meta("intent", "Progress MOVEit Transfer probe")

if path:find("human2%.aspx") then
  flag("moveit-cl0p-webshell")
  meta("intent", "MOVEit Cl0p human2.aspx webshell access (CVE-2023-34362 post-exploitation)")
  send("404 Not Found", "text/html", "<html><body>Not Found</body></html>")
elseif path:find("moveitisapi") or path:find("/api/v1/") or path:find("guestaccess%.aspx") then
  flag("moveit-api-probe")
  if (path .. body):find("X%-siLock") or (path .. body):find("INSERT") or (path .. body):find("CAST%(") then
    flag("moveit-cve-2023-34362")
    meta("intent", "MOVEit SQL injection surface (CVE-2023-34362)")
  end
  send("200 OK", "application/json", '{"errorCode":0,"errorDescription":""}')
elseif method == "POST" and (path:find("login") or path:find("human.aspx")) then
  local u = body:match("username=([^&\r\n]+)") or body:match("Username=([^&\r\n]+)")
  local p = body:match("password=([^&\r\n]+)") or body:match("Password=([^&\r\n]+)")
  if u then meta("auth_user", u) end
  if p then meta("auth_pass", p) end
  send("200 OK", "text/html", "<html><head><title>MOVEit Transfer - Sign In</title></head><body></body></html>")
else
  send("200 OK", "text/html",
    "<html><head><title>MOVEit Transfer</title></head><body>Progress MOVEit Transfer</body></html>")
end
