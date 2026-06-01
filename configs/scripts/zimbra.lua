-- Fake Zimbra Collaboration (handler: lua, HTTP). Zimbra webmail/admin is a
-- perennial target (CVE-2022-27925, CVE-2024-45519, autodiscover probes).
-- Serves the login page + autodiscover stub, captures login + the
-- mboximport/admin probes. Nothing is executed.
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
  if body:find("username=") or body:find("loginOp=") then flag("zimbra-login-attempt") end
end
local ver = rng:choice({ "9.0.0", "8.8.15", "10.0.6" })
local function send(code, ctype, b)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ctype .. "\r\n")
  conn:write("Content-Length: " .. tostring(#b) .. "\r\nConnection: close\r\n\r\n" .. b)
end
flag("zimbra-access")
path = path or "/"
local p = string.lower(path)
if p:find("/service/extension/backup/mboximport") then
  flag("zimbra-mboximport-probe") -- CVE-2022-27925 traversal upload surface
  send("401 Unauthorized", "text/html", "<html><body>401</body></html>")
elseif p:find("/autodiscover") then
  flag("zimbra-autodiscover-probe")
  send("200 OK", "text/xml", "<?xml version=\"1.0\"?><Autodiscover/>")
elseif p:find("/zimbraadmin") or p:find(":7071") then
  flag("zimbra-admin-probe")
  send("200 OK", "text/html", "<html><title>Zimbra Administration</title><body>Zimbra " .. ver .. "</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Zimbra Web Client Sign In</title></head>" ..
    "<body><form method='post' action='/zimbra/'><input name='username'>" ..
    "<input type='password' name='password'></form></body></html>")
end
