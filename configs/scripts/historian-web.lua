-- Fake process-historian web (handler: lua, HTTP 80). OSIsoft/AVEVA PI Vision
-- and PI Web API expose the entire process-data history of a plant. Answers
-- the PI Web API root, captures the bearer token and probed path. Nothing real
-- is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("pi_auth", (h:gsub("[\r\n]", "")))
    flag("historian-auth-attempt")
  end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("historian-access")
path = path or "/"
if path:find("^/piwebapi/?$") then
  send("200 OK", "application/json", '{"Links":{"Self":"https://pi/piwebapi","System":"https://pi/piwebapi/system"}}')
elseif path:find("^/piwebapi/") or path:find("PIVision") then
  meta("historian_path", path)
  flag("historian-data-access")
  send("401 Unauthorized", "application/json", '{"Errors":["Unauthorized"]}')
else
  send("200 OK", "text/html", "<html><head><title>PI Vision</title></head><body>AVEVA PI Vision</body></html>")
end
