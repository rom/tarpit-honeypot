-- Fake SquirrelMail (handler: lua, HTTP). Legacy webmail, brute-forced and probed
-- for CVE-2018-14955 / CVE-2017-7692 (sendmail command injection). Serves the
-- recognizable login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("login_username=([^&]*)") if u then meta("auth_user", u); flag("squirrelmail-login-attempt") end end
local p = string.lower(path)
flag("squirrelmail-access")
if p:find("/src/redirect.php") or p:find("/src/login.php") then flag("squirrelmail-login-probe") end
local html = "<html><head><title>SquirrelMail - Login</title></head><body>SquirrelMail</body></html>"
conn:write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: SQMSESSID=" .. rng:hex(26) .. "; path=/\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
