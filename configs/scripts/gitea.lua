-- Fake Gitea (handler: lua, HTTP 3000). Self-hosted Git with a history of
-- exposed instances + CVEs (e.g. CVE-2024-6886 stored XSS, git-hook RCE on
-- older builds). Greets with the Gitea cookie/version, captures probed paths,
-- API token headers, and any sign-in POST. Nothing is executed.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then
    clen = tonumber((h:match(":%s*(%d+)"))) or 0
  end
  if hl:find("^authorization:") then
    meta("gitea_auth", (h:gsub("[\r\n]", "")))
    flag("gitea-auth-attempt")
  end
end

if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  local user = body:match("user_name=([^&]*)") or body:match("username=([^&]*)")
  if user then
    meta("gitea_username", user)
    flag("gitea-login-attempt")
  end
end

local ver = rng:choice({ "1.21.11", "1.22.1", "1.20.6", "1.19.4" })
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: \r\n")
  conn:write("Set-Cookie: i_like_gitea=" .. rng:hex(16) .. "; Path=/; HttpOnly\r\n")
  conn:write("X-Frame-Options: SAMEORIGIN\r\nContent-Type: " .. ctype .. "; charset=utf-8\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

flag("gitea-access")
path = path or "/"
local p = string.lower(path)
if p:find("^/api/v1") then
  meta("gitea_api_path", path)
  flag("gitea-api-probe")
  send("401 Unauthorized", "application/json", '{"message":"token is required","url":"https://gitea.com/api/swagger"}')
elseif p:find("^/user/login") or method == "POST" then
  flag("gitea-login-attempt")
  send("200 OK", "text/html", "<html><title>Sign In - Gitea</title><body>Username or password incorrect</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>Gitea: Git with a cup of tea</title>" ..
    "<meta name='generator' content='Gitea " .. ver .. "'></head>" ..
    "<body><h1>Gitea</h1><a href='/user/login'>Sign In</a></body></html>")
end
