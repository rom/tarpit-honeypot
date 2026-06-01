-- Fake ThinkPHP app (handler: lua, HTTP). ThinkPHP's multiple RCE chains
-- (CVE-2018-20062, CVE-2019-9082, the invokefunction/call_user_func bug) make
-- it one of the most relentlessly scanned PHP frameworks by IoT/DDoS botnets.
-- Captures the classic invokefunction / index/think probes. Nothing is run.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
end

local ver = rng:choice({ "5.0.23", "5.1.31", "6.0.12", "5.0.10" })
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: Apache\r\nX-Powered-By: PHP/7.4.33\r\n")
  conn:write("Content-Type: text/html; charset=utf-8\r\nContent-Length: " .. tostring(#body))
  conn:write("\r\nConnection: close\r\n\r\n" .. body)
end

flag("thinkphp-access")
path = path or "/"
local full = string.lower(path .. " " .. (reqline or ""))
if full:find("invokefunction") or full:find("call_user_func") or full:find("s=index/\\think") then
  flag("thinkphp-rce-attempt") -- the invokefunction RCE primitive
  meta("thinkphp_probe", path)
  send("200 OK", "<html><body>" .. rng:choice({ "phpinfo()", "ThinkPHP" }) .. "</body></html>")
elseif full:find("captcha") or full:find("?s=") then
  flag("thinkphp-module-probe")
  meta("thinkphp_probe", path)
  send("200 OK", "<html><body>ThinkPHP V" .. ver .. "</body></html>")
else
  send("200 OK", "<html><head><title>ThinkPHP</title></head><body>" ..
    ":) ThinkPHP V" .. ver .. "<br/>十年磨一剑</body></html>")
end
