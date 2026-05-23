-- Fake Grafana (handler: lua, HTTP 3000). Grafana is a perennial target
-- (CVE-2021-43798 path traversal, default admin/admin). Serves a believable
-- login page + /api/health, and captures POST /login credentials. Nothing
-- authenticates.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local n = string.lower(h):match("^content%-length:%s*(%d+)")
  if n then clen = tonumber(n) end
end
local body_in = ""
if clen > 0 and clen < 8192 then body_in = conn:read(clen) or "" end

local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

path = path or "/"
if path:find("^/api/health") then
  send("200 OK", "application/json", '{"commit":"abcd123","database":"ok","version":"10.4.2"}')
elseif method == "POST" and path:find("/login") then
  if #body_in > 0 then meta("login_body", body_in) end
  flag("grafana-login-attempt")
  send("401 Unauthorized", "application/json", '{"message":"Invalid username or password"}')
elseif path:find("%.%./") or path:find("%%2e%%2e") then
  flag("grafana-path-traversal")
  send("404 Not Found", "text/plain", "")
else
  send("200 OK", "text/html",
    "<html><head><title>Grafana</title></head><body><div class=login>Welcome to Grafana</div></body></html>")
end
