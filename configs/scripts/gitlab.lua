-- Fake GitLab (handler: lua, HTTP 80). A self-hosted GitLab is source code +
-- CI secrets and has had several critical RCE / account-takeover CVEs. Greets
-- as gitlab-workhorse, captures the probed path, the sign-in attempts, and any
-- API token. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local lh = string.lower(h)
  if lh:find("^private%-token:") or lh:find("^authorization:") then
    meta("gitlab_token", (h:gsub("[\r\n]", "")))
    flag("gitlab-token-presented")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: nginx\r\nX-Gitlab-Meta: gitlab-workhorse\r\n")
  conn:write("Content-Type: " .. ct .. "\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end
flag("gitlab-access")
path = path or "/"
if path:find("^/api/v4/version") then
  send("200 OK", "application/json", '{"version":"16.11.1","revision":"a1b2c3d"}')
elseif path:find("^/api/") then
  meta("gitlab_path", path)
  flag("gitlab-api-access")
  send("401 Unauthorized", "application/json", '{"message":"401 Unauthorized"}')
elseif path:find("^/users/sign_in") or method == "POST" then
  flag("gitlab-login-attempt")
  send("422 Unprocessable Entity", "text/html", "<html><body>Invalid login or password.</body></html>")
else
  send("200 OK", "text/html", "<html><head><title>GitLab</title></head><body>Sign in to GitLab</body></html>")
end
