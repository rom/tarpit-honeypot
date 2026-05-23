-- Fake HashiCorp Vault (handler: lua, HTTP 8200). An exposed/unsealed Vault
-- is the keys to the kingdom. Answers sys/health + seal-status, captures the
-- X-Vault-Token and any path probed. Nothing is stored.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^x%-vault%-token:") then
    meta("vault_token", (h:gsub("[\r\n]", "")))
    flag("vault-token-presented")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("vault-api-access")
path = path or "/"
if path:find("^/v1/sys/health") then
  send("200 OK", '{"initialized":true,"sealed":false,"standby":false,"version":"1.16.2","cluster_name":"vault-prod"}')
elseif path:find("^/v1/sys/seal%-status") then
  send("200 OK", '{"type":"shamir","initialized":true,"sealed":false,"t":3,"n":5,"version":"1.16.2"}')
elseif path:find("^/v1/") then
  flag("vault-secret-access")
  send("403 Forbidden", '{"errors":["permission denied"]}')
else
  send("404 Not Found", '{"errors":[]}')
end
