-- Fake TYPO3 CMS (handler: lua, HTTP). TYPO3 backend (/typo3) is brute-forced and
-- probed for extension RCEs and the install-tool. Serves the recognizable TYPO3
-- backend login + captures creds.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"
local clen = 0
for _ = 1, 50 do local h = conn:readline() if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end end
if clen > 0 then if clen > 8192 then clen = 8192 end local b = conn:read(clen) or "" meta("post_body", b)
  local u = b:match("username=([^&]*)") if u then meta("auth_user", u); flag("typo3-login-attempt") end end
local p = string.lower(path)
flag("typo3-access")
if p:find("/typo3/install.php") then flag("typo3-installtool-probe") end
if p:find("/typo3/") then flag("typo3-backend-probe") end
local html = "<html><head><title>TYPO3 CMS Login</title></head><body>TYPO3</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nSet-Cookie: be_typo_user=" .. rng:hex(20) .. "; path=/; HttpOnly\r\nConnection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
