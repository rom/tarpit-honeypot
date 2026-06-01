-- Fake Splunk web (handler: lua, HTTP 8000). Splunk Enterprise is a high-value
-- target — CVE-2024-36991 path traversal, REST API abuse, credential theft.
-- Serves the login + a believable server-info endpoint, captures login POSTs
-- and the en-US path-traversal probe. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  local user = body:match("username=([^&]*)")
  if user then
    meta("splunk_user", user)
    flag("splunk-login-attempt")
  end
end
local ver = rng:choice({ "9.1.2", "9.2.1", "8.2.12", "9.0.5" })
local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Splunkd\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#b))
  conn:write("\r\nConnection: close\r\n\r\n" .. b)
end
flag("splunk-access")
path = path or "/"
local p = string.lower(path)
if p:find("/modules/messaging/") or p:find("%.%./") or p:find("c:%.%.") then
  flag("splunk-traversal-probe") -- CVE-2024-36991 style
  send("404 Not Found", "text/html", "<html><body>Not found</body></html>")
elseif p:find("/services/server/info") or p:find("/services/") then
  flag("splunk-rest-probe")
  send("401 Unauthorized", "text/xml", "<response><messages><msg type=\"WARN\">call requires authentication</msg></messages></response>")
elseif p:find("/en%-us/account/login") or p:find("/account/login") then
  send("200 OK", "text/html", "<html><title>Login | Splunk</title><body>Splunk " .. ver .. "</body></html>")
else
  send("303 See Other", "text/html", "")
end
