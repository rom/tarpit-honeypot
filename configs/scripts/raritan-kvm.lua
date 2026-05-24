-- Fake Raritan Dominion KVM-over-IP web UI (handler: lua, HTTP 443). A KVM-
-- over-IP switch gives screen/keyboard control of every attached server. Answers
-- the Dominion login, captures the attempt and probed path. Nothing real.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("raritan_auth", (h:gsub("[\r\n]", "")))
    flag("raritan-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Raritan\r\nContent-Type: text/html\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("raritan-access")
path = path or "/"
if path:find("/auth") or method == "POST" or path:find("[Ll]ogin") then
  flag("raritan-login-attempt")
  send("200 OK", "<html><body>Authentication Failure</body></html>")
elseif path:find("[Tt]arget") or path:find("[Pp]ort") then
  meta("raritan_path", path)
  flag("raritan-kvm-access")
  send("401 Unauthorized", "<html><body>Not authorized</body></html>")
else
  send("200 OK", "<html><head><title>Dominion KX III</title></head><body>Raritan Dominion KX</body></html>")
end
