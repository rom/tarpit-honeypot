-- Fake Jupyter Notebook/Lab (handler: lua, HTTP 8888). An unauthenticated
-- (token-less) Jupyter is direct code execution, so any reach here is high
-- signal. Serves the login page + /api version, and captures token / login
-- attempts. Nothing runs.

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
if clen > 0 and clen < 8192 then meta("login_body", conn:read(clen) or "") end

local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: TornadoServer/6.4\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

flag("jupyter-access")
path = path or "/"
if path:find("^/api/?$") or path:find("^/api/status") then
  send("200 OK", "application/json", '{"version":"7.2.1"}')
elseif path:find("^/api/contents") or path:find("^/api/sessions") or path:find("^/api/kernels") then
  flag("jupyter-api-access")
  send("403 Forbidden", "application/json", '{"message":"Forbidden"}')
elseif method == "POST" and path:find("/login") then
  flag("jupyter-login-attempt")
  send("401 Unauthorized", "text/html", "<html><body>Invalid credentials or token</body></html>")
else
  send("200 OK", "text/html",
    "<html><head><title>Jupyter Notebook</title></head><body><h1>Password or token:</h1><form method=post action=/login></form></body></html>")
end
