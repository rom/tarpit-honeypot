-- Fake CODESYS web server / WebVisu (handler: lua, HTTP 8080). CODESYS is the
-- runtime behind hundreds of PLC brands; its web server / WebVisu has had
-- critical unauth RCE CVEs. Answers the WebVisu start page, captures the probed
-- path. Nothing real is served.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
end
local function send(code, ct, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: CODESYS\r\nContent-Type: " .. ct .. "\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("codesys-access")
path = path or "/"
if path:find("webvisu") or path:find("%.htm") then
  meta("codesys_path", path)
  flag("codesys-webvisu-access")
  send("200 OK", "text/html", "<html><head><title>CODESYS WebVisu</title></head><body>WebVisu</body></html>")
elseif method == "POST" then
  meta("codesys_path", path)
  flag("codesys-command")
  send("200 OK", "application/octet-stream", "")
else
  send("200 OK", "text/html", "<html><head><title>CODESYS</title></head><body>CODESYS Control</body></html>")
end
