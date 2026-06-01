-- Fake Node-RED (handler: lua, HTTP 1880). An exposed Node-RED flow editor is
-- remote code execution: an attacker imports a flow with an `exec`/`function`
-- node. Serves the editor's settings endpoint, captures flow deployments and
-- exec-node injection. Nothing is executed.
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
  if clen > 16384 then clen = 16384 end
  local body = conn:read(clen) or ""
  local low = body:lower()
  if low:find('"type":"exec"') or low:find('"type":"function"') then
    flag("nodered-code-injection") -- exec/function node = RCE on deploy
    meta("nodered_flow", body:sub(1, 512))
  elseif low:find('"flows"') or path:lower():find("/flows") then
    flag("nodered-flow-deploy")
  end
end

local ver = rng:choice({ "3.1.0", "3.0.2", "2.2.2", "3.1.3" })
local function send(code, ctype, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nX-Powered-By: Express\r\n")
  conn:write("Content-Type: " .. ctype .. "\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("nodered-access")
path = path or "/"
local p = string.lower(path)
if p:find("/settings") then
  flag("nodered-recon")
  send("200 OK", "application/json", '{"httpNodeRoot":"/","version":"' .. ver ..
    '","context":{"default":"memory"},"editorTheme":{"projects":{"enabled":false}}}')
elseif p:find("/flows") then
  send("200 OK", "application/json", '[]')
elseif p:find("/auth/login") then
  send("200 OK", "application/json", '{"type":"credentials","prompts":[{"id":"username","type":"text"}]}')
else
  send("200 OK", "text/html", "<html><head><title>Node-RED</title></head><body>Node-RED " .. ver .. "</body></html>")
end
