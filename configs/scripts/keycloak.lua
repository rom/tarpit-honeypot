-- Fake Keycloak (handler: lua, HTTP 8080). Keycloak is the identity provider —
-- its admin console and token endpoint are a prime account-takeover target.
-- Answers the realm OIDC discovery, captures token-endpoint credential grants
-- and the admin path probed. Nothing real is issued.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("keycloak_auth", (h:gsub("[\r\n]", "")))
    flag("keycloak-auth-attempt")
  end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("keycloak-access")
path = path or "/"
if path:find("/realms/[^/]+/%.well%-known/openid%-configuration") then
  send("200 OK", '{"issuer":"https://idp/realms/master","token_endpoint":"https://idp/realms/master/protocol/openid-connect/token"}')
elseif path:find("/protocol/openid%-connect/token") or method == "POST" then
  flag("keycloak-token-request")
  send("401 Unauthorized", '{"error":"invalid_client","error_description":"Invalid client credentials"}')
elseif path:find("/admin/") then
  meta("keycloak_path", path)
  flag("keycloak-admin-access")
  send("401 Unauthorized", '{"error":"HTTP 401 Unauthorized"}')
else
  send("200 OK", '{"realm":"master"}')
end
