-- Fake WordPress (handler: lua, HTTP). The most relentlessly attacked CMS on
-- the internet — wp-login.php brute force, xmlrpc.php amplification, and
-- wp-json user enumeration. Captures login POSTs, xmlrpc method calls, and the
-- REST user-enum probe. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
local body = ""
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  body = conn:read(clen) or ""
end

local ver = rng:choice({ "6.4.3", "6.5.2", "6.3.1", "5.9.8" })
local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nX-Powered-By: PHP/8.1.27\r\n")
  conn:write("Link: <https://example/wp-json/>; rel=\"https://api.w.org/\"\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b))
  conn:write("\r\nConnection: close\r\n\r\n" .. b)
end

flag("wordpress-access")
path = path or "/"
local p = string.lower(path)
if p:find("wp%-login%.php") then
  local user = body:match("log=([^&]*)")
  if user then meta("wp_user", user) end
  local pass = body:match("pwd=([^&]*)")
  if pass then meta("wp_pass", pass) end
  if user or pass then flag("wordpress-login-attempt") end
  send("200 OK", "text/html", "<html><title>Log In &lsaquo; WordPress</title><body><form id='loginform'></form></body></html>")
elseif p:find("xmlrpc%.php") then
  flag("wordpress-xmlrpc")
  if body:lower():find("wp%.getusersblogs") or body:lower():find("system%.multicall") then
    flag("wordpress-xmlrpc-bruteforce") -- multicall = amplified credential brute force
  end
  send("200 OK", "text/xml", "<?xml version=\"1.0\"?><methodResponse><params><param><value><string>WP</string></value></param></params></methodResponse>")
elseif p:find("/wp%-json/wp/v2/users") then
  flag("wordpress-user-enum")
  send("200 OK", "application/json", '[{"id":1,"name":"admin","slug":"admin"}]')
elseif p:find("/wp%-json") then
  send("200 OK", "application/json", '{"name":"Blog","description":"Just another WordPress site","gmt_offset":0}')
else
  send("200 OK", "text/html", "<html><head><meta name='generator' content='WordPress " .. ver ..
    "'><title>Blog</title></head><body><a href='/wp-login.php'>Log in</a></body></html>")
end
